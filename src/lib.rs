//! Constant time AES.
//!
//! # Warning
//!
//! This is low-level cryptography. It must only be used for
//! implementing high-level constructions. It must only be used
//! as a fallback for platforms without AES intrinsics. Do NOT
//! use this code unless you know exactly what you are doing. If
//! in doubt, use [`aes-gcm`] instead.
//!
//! [`aes-gcm`]: https://crates.io/crates/aes-gcm

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

pub mod aes32;
pub mod aes64;
mod tests;

/// The size in bytes of an AES block.
pub const BLOCK_SIZE: usize = 16;

/// An AES block.
pub type Block = [u8; BLOCK_SIZE];

cfg_if::cfg_if! {
    if #[cfg(feature = "zeroize")] {
        pub(crate) use zeroize::Zeroizing;
    } else {
        pub(crate) struct Zeroizing<T>(core::marker::PhantomData<T>);
        impl<T> Zeroizing<T> {
            #[inline(always)]
            pub fn new(v: T) -> T {
                v
            }
        }
    }
}

pub(crate) const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
#[inline(always)]
#[allow(clippy::arithmetic_side_effects)]
pub(crate) const fn as_chunks_mut<T, const N: usize>(data: &mut [T]) -> (&mut [[T; N]], &mut [T]) {
    const { assert!(N > 0) }

    let len_rounded_down = (data.len() / N) * N;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { data.split_at_mut_unchecked(len_rounded_down) };
    let new_len = head.len() / N;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { core::slice::from_raw_parts_mut(head.as_mut_ptr().cast(), new_len) };
    (head, tail)
}
