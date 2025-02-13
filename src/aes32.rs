/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 * Copyright (c) 2025 Eric Lagergren
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Constant time 32-bit bitsliced AES from [BearSSL].
//!
//! [BearSSL]: https://www.bearssl.org/gitweb/?p=BearSSL;a=tree;h=7d854167e69c8fe84add518ee0ddc672bbe2b2d7;hb=HEAD

use core::mem::{self, MaybeUninit};

use crate::{as_chunks_mut, Block, Zeroizing, BLOCK_SIZE, RCON};

macro_rules! impl_aes {
    (
        $name:ident,
        $k:literal,
        $n:literal,
        $doc:expr $(,)?
    ) => {
        #[doc = $doc]
        #[derive(Clone, Debug)]
        pub struct $name {
            sk: [[u32; 8]; $n],
        }

        impl $name {
            /// The size in octets of an AES key.
            pub const KEY_SIZE: usize = $k;

            /// The size in octets of an AES block.
            pub const BLOCK_SIZE: usize = BLOCK_SIZE;

            /// Initializes the AES block cipher.
            //#[inline]
            pub fn new(key: &[u8; $k]) -> Self {
                let mut rk = Zeroizing::new([[0; 4]; $n]);
                key_schedule(&mut rk, key);

                let sk = {
                    // Even though we write to each element in
                    // `sk` without reading any of them, the
                    // compiler still initializes it with zeros,
                    // which wastes everybody's time. So, hold
                    // the compiler's hand and use `MaybeUninit`.
                    let mut sk = [[MaybeUninit::uninit(); 8]; $n];
                    expand_keys_uninit(&mut sk, &rk);
                    // SAFETY: `expand_keys` initialized every
                    // element in `sk`.
                    unsafe { mem::transmute::<[[MaybeUninit<u32>; 8]; $n], [[u32; 8]; $n]>(sk) }
                };

                Self { sk }
            }

            /// Encrypts one block.
            #[inline]
            pub fn encrypt_block(&self, block: &mut Block) {
                encrypt_blocks(block, &mut [0; BLOCK_SIZE], &self.sk);
            }

            /// Encrypts one or more blocks.
            #[inline]
            pub fn encrypt_blocks(&self, blocks: &mut [Block]) {
                let (head, tail) = as_chunks_mut::<Block, 2>(blocks);
                for chunk in head {
                    let [ref mut block1, ref mut block2] = chunk;
                    encrypt_blocks(block1, block2, &self.sk);
                }
                if let Some(block1) = tail.first_mut() {
                    encrypt_blocks(block1, &mut [0; BLOCK_SIZE], &self.sk);
                }
            }

            /// Decrypts one block.
            #[inline]
            pub fn decrypt_block(&self, block: &mut Block) {
                decrypt_blocks(block, &mut [0; BLOCK_SIZE], &self.sk);
            }

            /// Decrypts one or more blocks.
            #[inline]
            pub fn decrypt_blocks(&self, blocks: &mut [Block]) {
                let (head, tail) = as_chunks_mut::<Block, 2>(blocks);
                for chunk in head {
                    let [ref mut block1, ref mut block2] = chunk;
                    decrypt_blocks(block1, block2, &self.sk);
                }
                if let Some(block1) = tail.first_mut() {
                    decrypt_blocks(block1, &mut [0; BLOCK_SIZE], &self.sk);
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl zeroize::ZeroizeOnDrop for $name {}

        impl Drop for $name {
            #[inline]
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                // SAFETY: `self` is a flat type and will not be
                // used after the method returns.
                unsafe {
                    zeroize::zeroize_flat_type(self);
                }
            }
        }
    };
}
impl_aes!(Aes128, 16, 11, "AES-128");
impl_aes!(Aes192, 24, 13, "AES-192");
impl_aes!(Aes256, 32, 15, "AES-256");

/// Performs the AES key schedule, writing the round keys to
/// `rk`.
///
/// `K` and `N` must be one of:
/// - 16 and 11 for AES-128
/// - 24 and 13 for AES-192
/// - 32 and 15 for AES-256
#[inline]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "The compiler can prove the indices are in bounds."
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "The compiler can prove none of the arithmetic overflows, panics, etc."
)]
pub fn key_schedule<const K: usize, const N: usize>(rk: &mut [[u32; 4]; N], key: &[u8; K]) {
    const {
        assert!((K == 16 && N == 11) || (K == 24 && N == 13) || (K == 32 && N == 15));
    }

    // NB: Each word in the AES key schedule is repeated twice.
    // E.g., `w = [w0, w0, w1, w1, ..., wN, wN]`.
    let mut wt = Zeroizing::new([[0u32; 8]; N]);
    let w = wt.as_flattened_mut();

    // The first `nk*2` words in `w` are they key itself.
    for (w, k) in w.chunks_exact_mut(2).zip(key.chunks_exact(4)) {
        let tmp = u32::from_le_bytes(k.try_into().unwrap());
        w[0] = tmp;
        w[1] = tmp;
    }

    let nk = key.len() / 4;
    let mut i = nk;
    let mut j = nk * 2;
    while j < w.len() {
        let mut tmp = w[j - 2];
        if i % nk == 0 {
            tmp = sub_word(tmp.rotate_right(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            tmp = sub_word(tmp);
        }
        w[j] = w[j - (nk * 2)] ^ tmp;
        w[j + 1] = w[j - (nk * 2)] ^ tmp;
        i += 1;
        j += 2;
    }

    for (rk, w) in rk
        .as_flattened_mut()
        .chunks_exact_mut(4)
        .zip(w.chunks_exact_mut(8))
    {
        ortho(w.try_into().unwrap());
        for (rk, w) in rk.iter_mut().zip(w.chunks_exact(2)) {
            *rk = (w[0] & 0x55555555) | (w[1] & 0xAAAAAAAA);
        }
    }
}

#[inline(always)]
fn sub_word(x: u32) -> u32 {
    let mut q = [x; 8];
    ortho(&mut q);
    sub_bytes(&mut q);
    ortho(&mut q);
    q[0]
}

/// Expands AES round keys.
///
/// `N` must be one of
/// - 11 for AES-128
/// - 13 for AES-192
/// - 15 for AES-256
#[inline]
pub fn expand_keys<const N: usize>(sk: &mut [[u32; 8]; N], rk: &[[u32; 4]; N]) {
    const {
        assert!(N == 11 || N == 13 || N == 15);
    }

    // SAFETY: `u32` and `MaybeUninit<u32>` have an identical
    // memory layout. `sk` is already initialized and
    // `expand_keys_uninit` writes to every element of `sk`.
    let sk = unsafe { &mut *((sk as *mut [[u32; 8]; N]).cast()) };
    expand_keys_uninit::<N>(sk, rk);
}

#[inline(always)]
#[allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove the indices are in bounds."
)]
fn expand_keys_uninit<const N: usize>(sk: &mut [[MaybeUninit<u32>; 8]; N], rk: &[[u32; 4]; N]) {
    const {
        assert!(N == 11 || N == 13 || N == 15);
    }

    for (sk, &rk) in sk
        .as_flattened_mut()
        .chunks_exact_mut(2)
        .zip(rk.as_flattened())
    {
        let x = rk & 0x55555555;
        let y = rk & 0xAAAAAAAA;
        sk[0].write(x | (x << 1));
        sk[1].write(y | (y >> 1));
    }
}

/// Encrypts two blocks.
///
/// `sk` must have been expanded by [`expand_key`].
///
/// `NR` must be one of:
/// - 11 for AES-128
/// - 13 for AES-192
/// - 15 for AES-256
#[inline(always)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "The compiler can prove the indices are in bounds."
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "The compiler can prove none of the arithmetic overflows."
)]
pub fn encrypt_blocks<const N: usize>(block1: &mut Block, block2: &mut Block, sk: &[[u32; 8]; N]) {
    const {
        assert!(N == 11 || N == 13 || N == 15);
    }

    let mut q = interleave_in(block1, block2);

    ortho(&mut q);
    add_round_key(&mut q, &sk[0]);
    for sk in &sk[1..sk.len() - 1] {
        sub_bytes(&mut q);
        shift_rows(&mut q);
        mix_columns(&mut q);
        add_round_key(&mut q, sk);
    }
    sub_bytes(&mut q);
    shift_rows(&mut q);
    add_round_key(&mut q, &sk[sk.len() - 1]);
    ortho(&mut q);

    interleave_out(block1, block2, &q);
}

/// Decrypts two blocks.
///
/// `sk` must have been expanded by [`expand_key`].
///
/// `NR` must be one of:
/// - 11 for AES-128
/// - 13 for AES-192
/// - 15 for AES-256
#[inline(always)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "The compiler can prove the indices are in bounds."
)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "The compiler can prove none of the arithmetic overflows."
)]
pub fn decrypt_blocks<const N: usize>(block1: &mut Block, block2: &mut Block, sk: &[[u32; 8]; N]) {
    const {
        assert!(N == 11 || N == 13 || N == 15);
    }

    let mut q = interleave_in(block1, block2);

    ortho(&mut q);
    add_round_key(&mut q, &sk[sk.len() - 1]);
    for sk in sk[1..sk.len() - 1].iter().rev() {
        inv_shift_rows(&mut q);
        inv_sub_bytes(&mut q);
        add_round_key(&mut q, sk);
        inv_mix_columns(&mut q);
    }
    inv_shift_rows(&mut q);
    inv_sub_bytes(&mut q);
    add_round_key(&mut q, &sk[0]);
    ortho(&mut q);

    interleave_out(block1, block2, &q);
}

/// Perform one full AES round on two blocks.
///
/// - `SubBytes`
/// - `ShiftRows
/// - `MixColumns`
/// - `AddRoundKey`
#[inline(always)]
pub fn enc_round(block1: &mut Block, block2: &mut Block, sk: &[u32; 8]) {
    let mut q = interleave_in(block1, block2);

    ortho(&mut q);
    sub_bytes(&mut q);
    shift_rows(&mut q);
    mix_columns(&mut q);
    add_round_key(&mut q, sk);
    ortho(&mut q);

    interleave_out(block1, block2, &q);
}

/// Perform one full AES round on two blocks.
///
/// - Inverse of `ShiftRows
/// - Inverse of `SubBytes`
/// - `AddRoundKey`
/// - Inverse of `MixColumns`
#[inline(always)]
pub fn dec_round(block1: &mut Block, block2: &mut Block, sk: &[u32; 8]) {
    let mut q = interleave_in(block1, block2);

    ortho(&mut q);
    inv_shift_rows(&mut q);
    sub_bytes(&mut q);
    add_round_key(&mut q, sk);
    inv_mix_columns(&mut q);
    ortho(&mut q);

    interleave_out(block1, block2, &q);
}

#[inline(always)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The compiler can prove the indices are in bounds."
)]
fn interleave_in(block1: &Block, block2: &Block) -> [u32; 8] {
    [
        u32::from_le_bytes(block1[0..4].try_into().unwrap()),
        u32::from_le_bytes(block2[0..4].try_into().unwrap()),
        u32::from_le_bytes(block1[4..8].try_into().unwrap()),
        u32::from_le_bytes(block2[4..8].try_into().unwrap()),
        u32::from_le_bytes(block1[8..12].try_into().unwrap()),
        u32::from_le_bytes(block2[8..12].try_into().unwrap()),
        u32::from_le_bytes(block1[12..16].try_into().unwrap()),
        u32::from_le_bytes(block2[12..16].try_into().unwrap()),
    ]
}

#[inline(always)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "The compiler can prove the indices are in bounds."
)]
fn interleave_out(block1: &mut Block, block2: &mut Block, q: &[u32; 8]) {
    block1[0..4].copy_from_slice(&q[0].to_le_bytes());
    block1[4..8].copy_from_slice(&q[2].to_le_bytes());
    block1[8..12].copy_from_slice(&q[4].to_le_bytes());
    block1[12..16].copy_from_slice(&q[6].to_le_bytes());

    block2[0..4].copy_from_slice(&q[1].to_le_bytes());
    block2[4..8].copy_from_slice(&q[3].to_le_bytes());
    block2[8..12].copy_from_slice(&q[5].to_le_bytes());
    block2[12..16].copy_from_slice(&q[7].to_le_bytes());
}

/// Perform bytewise orthogonalization of eight 32-bit words.
/// Bytes of q0..q7 are spread over all words: for a byte x that
/// occurs at rank i in q[j] (byte x uses bits 8*i to 8*i+7 in
/// q[j]), the bit of rank k in x (0 <= k <= 7) goes to q[k] at
/// rank 8*i+j.
///
/// This operation is an involution.
#[inline(always)]
fn ortho(q: &mut [u32; 8]) {
    macro_rules! swap {
        (2; $x:expr, $y:expr) => {
            swap!(0x55555555, 0xAAAAAAAA, 1, $x, $y)
        };
        (4; $x:expr, $y:expr) => {
            swap!(0x33333333, 0xCCCCCCCC, 2, $x, $y)
        };
        (8; $x:expr, $y:expr) => {
            swap!(0x0F0F0F0F, 0xF0F0F0F0, 4, $x, $y)
        };
        ($cl:literal, $ch:literal, $s:literal, $x:expr, $y:expr) => {
            let a = $x;
            let b = $y;
            $x = (a & $cl) | ((b & $cl) << $s);
            $y = ((a & $ch) >> $s) | (b & $ch);
        };
    }

    swap!(2; q[0], q[1]);
    swap!(2; q[2], q[3]);
    swap!(2; q[4], q[5]);
    swap!(2; q[6], q[7]);

    swap!(4; q[0], q[2]);
    swap!(4; q[1], q[3]);
    swap!(4; q[4], q[6]);
    swap!(4; q[5], q[7]);

    swap!(8; q[0], q[4]);
    swap!(8; q[1], q[5]);
    swap!(8; q[2], q[6]);
    swap!(8; q[3], q[7]);
}

/// `SubBytes`
///
/// The AES S-box, as a bitsliced constant-time version. The
/// input array consists in eight 32-bit words; 32 S-box
/// instances are computed in parallel. Bits 0 to 7 of each S-box
/// input (bit 0 is least significant) are spread over the words
/// 0 to 7, at the same rank.
#[inline(always)]
pub fn sub_bytes(q: &mut [u32; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// Inverse of `SubBytes`.
#[inline(always)]
pub fn inv_sub_bytes(q: &mut [u32; 8]) {
    let mut q0 = !q[0];
    let mut q1 = !q[1];
    let mut q2 = q[2];
    let mut q3 = q[3];
    let mut q4 = q[4];
    let mut q5 = !q[5];
    let mut q6 = !q[6];
    let mut q7 = q[7];

    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;

    sub_bytes(q);

    q0 = !q[0];
    q1 = !q[1];
    q2 = q[2];
    q3 = q[3];
    q4 = q[4];
    q5 = !q[5];
    q6 = !q[6];
    q7 = q[7];

    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

/// `ShiftRows`.
#[inline(always)]
pub fn shift_rows(q: &mut [u32; 8]) {
    for x in q {
        *x = (*x & 0x000000FF)
            | ((*x & 0x0000FC00) >> 2)
            | ((*x & 0x00000300) << 6)
            | ((*x & 0x00F00000) >> 4)
            | ((*x & 0x000F0000) << 4)
            | ((*x & 0xC0000000) >> 6)
            | ((*x & 0x3F000000) << 2);
    }
}

/// Inverse of `ShiftRows`.
#[inline(always)]
pub fn inv_shift_rows(q: &mut [u32; 8]) {
    for x in q {
        *x = (*x & 0x000000FF)
            | ((*x & 0x00003F00) << 2)
            | ((*x & 0x0000C000) >> 6)
            | ((*x & 0x000F0000) << 4)
            | ((*x & 0x00F00000) >> 4)
            | ((*x & 0x03000000) << 6)
            | ((*x & 0xFC000000) >> 2);
    }
}

/// `AddRoundKey`.
#[inline(always)]
pub fn add_round_key(q: &mut [u32; 8], rk: &[u32; 8]) {
    for (q, k) in q.iter_mut().zip(rk) {
        *q ^= *k;
    }
}

/// `MixColumns`.
#[inline(always)]
pub fn mix_columns(q: &mut [u32; 8]) {
    let q0 = q[0];
    let q1 = q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = q[5];
    let q6 = q[6];
    let q7 = q[7];

    let r0 = q0.rotate_left(24);
    let r1 = q1.rotate_left(24);
    let r2 = q2.rotate_left(24);
    let r3 = q3.rotate_left(24);
    let r4 = q4.rotate_left(24);
    let r5 = q5.rotate_left(24);
    let r6 = q6.rotate_left(24);
    let r7 = q7.rotate_left(24);

    q[0] = q7 ^ r7 ^ r0 ^ (q0 ^ r0).rotate_right(16);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ (q1 ^ r1).rotate_right(16);
    q[2] = q1 ^ r1 ^ r2 ^ (q2 ^ r2).rotate_right(16);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ (q3 ^ r3).rotate_right(16);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ (q4 ^ r4).rotate_right(16);
    q[5] = q4 ^ r4 ^ r5 ^ (q5 ^ r5).rotate_right(16);
    q[6] = q5 ^ r5 ^ r6 ^ (q6 ^ r6).rotate_right(16);
    q[7] = q6 ^ r6 ^ r7 ^ (q7 ^ r7).rotate_right(16);
}

/// Inverse of `MixColumns`.
#[inline(always)]
pub fn inv_mix_columns(q: &mut [u32; 8]) {
    let q0 = q[0];
    let q1 = q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = q[5];
    let q6 = q[6];
    let q7 = q[7];

    let r0 = q0.rotate_left(24);
    let r1 = q1.rotate_left(24);
    let r2 = q2.rotate_left(24);
    let r3 = q3.rotate_left(24);
    let r4 = q4.rotate_left(24);
    let r5 = q5.rotate_left(24);
    let r6 = q6.rotate_left(24);
    let r7 = q7.rotate_left(24);

    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ (q0 ^ q5 ^ q6 ^ r0 ^ r5).rotate_right(16);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ (q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6).rotate_right(16);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ (q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7).rotate_right(16);
    q[3] = q0
        ^ q1
        ^ q2
        ^ q5
        ^ q6
        ^ r0
        ^ r2
        ^ r3
        ^ r5
        ^ (q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7).rotate_right(16);
    q[4] = q1
        ^ q2
        ^ q3
        ^ q5
        ^ r1
        ^ r3
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ (q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6).rotate_right(16);
    q[5] = q2
        ^ q3
        ^ q4
        ^ q6
        ^ r2
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ (q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7).rotate_right(16);
    q[6] =
        q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7 ^ (q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7).rotate_right(16);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ (q4 ^ q5 ^ q7 ^ r4 ^ r7).rotate_right(16);
}

/// Optimized code for SNOW-V.
#[cfg(feature = "snowv")]
#[cfg_attr(docsrs, doc(cfg(feature = "snowv")))]
pub mod snowv {
    use super::{mix_columns, ortho, shift_rows, sub_bytes};

    /// Same as [`enc_round`], but optimized for SNOW-V.
    #[inline(always)]
    pub fn enc_round(block1: &[u32; 4], block2: &[u32; 4]) -> ([u32; 4], [u32; 4]) {
        #[rustfmt::skip]
        let mut q = [
            block1[0], block2[0], 
            block1[1], block2[1], 
            block1[2], block2[2], 
            block1[3], block2[3],
        ];

        ortho(&mut q);
        sub_bytes(&mut q);
        shift_rows(&mut q);
        mix_columns(&mut q);
        ortho(&mut q);

        let r1 = [q[0], q[2], q[4], q[6]];
        let r2 = [q[1], q[3], q[5], q[7]];
        (r1, r2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{impl_acvp, impl_test_aes, AES_128_TESTS, AES_192_TESTS, AES_256_TESTS};

    #[test]
    fn test_crypt_aes128() {
        for (i, &(key, pt, ct)) in AES_128_TESTS.iter().enumerate() {
            let aes = Aes128::new(&key);
            let mut block1 = pt;
            aes.encrypt_block(&mut block1);
            assert_eq!(block1, ct, "#{i}: `encrypt_block`");
            aes.decrypt_block(&mut block1);
            assert_eq!(block1, pt, "#{i}: `decrypt_block`");
        }
    }

    #[test]
    fn test_crypt_aes192() {
        for (i, &(key, pt, ct)) in AES_192_TESTS.iter().enumerate() {
            let aes = Aes192::new(&key);
            let mut block1 = pt;
            aes.encrypt_block(&mut block1);
            assert_eq!(block1, ct, "#{i}: `encrypt_block`");
            aes.decrypt_block(&mut block1);
            assert_eq!(block1, pt, "#{i}: `decrypt_block`");
        }
    }

    #[test]
    fn test_crypt_aes256() {
        for (i, &(key, pt, ct)) in AES_256_TESTS.iter().enumerate() {
            let aes = Aes256::new(&key);
            let mut block1 = pt;
            aes.encrypt_block(&mut block1);
            assert_eq!(block1, ct, "#{i}: `encrypt_block`");
            aes.decrypt_block(&mut block1);
            assert_eq!(block1, pt, "#{i}: `decrypt_block`");
        }
    }

    impl_test_aes!(Aes);
    impl_acvp!(test_acvp, Aes);
}
