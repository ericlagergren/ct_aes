#![cfg(test)]

use hex_literal::hex;
use serde::Deserialize;

pub(crate) type TestCase<'a, const N: usize> = ([u8; N], [u8; 16], [u8; 16]);

pub(crate) static AES_128_TESTS: &[TestCase<'_, 16>] = &[
    (
        hex!("2b7e151628aed2a6abf7158809cf4f3c"),
        hex!("3243f6a8885a308d313198a2e0370734"),
        hex!("3925841d02dc09fbdc118597196a0b32"),
    ),
    (
        hex!("000102030405060708090a0b0c0d0e0f"),
        hex!("00112233445566778899aabbccddeeff"),
        hex!("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
];

pub(crate) static AES_192_TESTS: &[TestCase<'_, 24>] = &[(
    hex!("000102030405060708090a0b0c0d0e0f1011121314151617"),
    hex!("00112233445566778899aabbccddeeff"),
    hex!("dda97ca4864cdfe06eaf70a0ec0d7191"),
)];

pub(crate) static AES_256_TESTS: &[TestCase<'_, 32>] = &[(
    hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    hex!("00112233445566778899aabbccddeeff"),
    hex!("8ea2b7ca516745bfeafc49904b496089"),
)];

impl TestVectors {
    pub fn load() -> Self {
        static DATA: &str =
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/acvp.json"));
        serde_json::from_str(DATA).unwrap()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TestVectors {
    pub test_groups: Vec<TestGroup>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TestGroup {
    pub direction: String,
    #[serde(flatten)]
    pub tests: Tests,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "testType", content = "tests")]
pub(crate) enum Tests {
    Aft(Vec<Aft>),
    Mct(Vec<Mct>),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Aft {
    pub tc_id: usize,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Mct {
    pub tc_id: usize,
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    #[serde(default = "Vec::new")]
    pub pt: Vec<u8>,
    #[serde(with = "hex::serde")]
    #[serde(default = "Vec::new")]
    pub ct: Vec<u8>,
    pub results_array: Vec<MctResult>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MctResult {
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub pt: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub ct: Vec<u8>,
}

macro_rules! impl_acvp {
    ($name:ident, $aes:ty) => {
        #[test]
        fn $name() {
            use $crate::{
                as_chunks_mut,
                tests::{Aft, Mct, TestVectors, Tests},
            };

            let vectors = TestVectors::load();
            for group in vectors.test_groups {
                match group.tests {
                    Tests::Aft(tests) => {
                        for Aft { tc_id, pt, key, ct } in tests {
                            let aes = <$aes>::new(&key);
                            let mut got = pt.clone();

                            let (blocks, tail) = as_chunks_mut::<_, BLOCK_SIZE>(&mut got);
                            assert!(tail.is_empty());

                            for block in blocks.iter_mut() {
                                aes.encrypt_block(block);
                            }
                            assert_eq!(blocks.as_flattened(), ct, "#{tc_id}");

                            for block in blocks.iter_mut() {
                                aes.decrypt_block(block);
                            }
                            assert_eq!(blocks.as_flattened(), pt, "#{tc_id}");

                            aes.encrypt_blocks(blocks);
                            assert_eq!(blocks.as_flattened(), ct, "#{tc_id}");

                            aes.decrypt_blocks(blocks);
                            assert_eq!(blocks.as_flattened(), pt, "#{tc_id}");
                        }
                    }
                    Tests::Mct(tests) => {
                        for Mct {
                            tc_id,
                            mut key,
                            mut pt,
                            mut ct,
                            results_array,
                            ..
                        } in tests
                        {
                            fn key_shuffle(key: &mut [u8], current: &[u8], prev: &[u8]) {
                                match key.len() {
                                    16 => {
                                        for (dst, src) in key.iter_mut().zip(&current[..16]) {
                                            *dst ^= *src;
                                        }
                                    }
                                    24 => {
                                        let (lhs, rhs) = key.split_at_mut(8);
                                        for (dst, src) in
                                            lhs.iter_mut().zip(&prev[prev.len() - 8..])
                                        {
                                            *dst ^= *src;
                                        }
                                        for (dst, src) in rhs.iter_mut().zip(&current[..16]) {
                                            *dst ^= *src;
                                        }
                                    }
                                    32 => {
                                        let (lhs, rhs) = key.split_at_mut(16);
                                        for (dst, src) in lhs.iter_mut().zip(&prev[..16]) {
                                            *dst ^= *src;
                                        }
                                        for (dst, src) in rhs.iter_mut().zip(&current[..16]) {
                                            *dst ^= *src;
                                        }
                                    }
                                    n => panic!("invalid key length: {n}"),
                                }
                            }

                            let mut pt = {
                                let (blocks, rest) = as_chunks_mut::<_, BLOCK_SIZE>(&mut pt);
                                assert!(rest.is_empty());
                                blocks.to_vec()
                            };
                            let mut ct = {
                                let (blocks, rest) = as_chunks_mut::<_, BLOCK_SIZE>(&mut ct);
                                assert!(rest.is_empty());
                                blocks.to_vec()
                            };

                            let encrypt = group.direction == "encrypt";
                            let mut prev = Vec::new();
                            for i in 0..100 {
                                assert_eq!(key, results_array[i].key, "#{tc_id},{i}");

                                if encrypt {
                                    assert_eq!(
                                        pt.as_flattened(),
                                        results_array[i].pt,
                                        "#{tc_id},{i}"
                                    );
                                } else {
                                    assert_eq!(
                                        ct.as_flattened(),
                                        results_array[i].ct,
                                        "#{tc_id},{i}"
                                    );
                                }

                                for j in 0..1000 {
                                    if j == 999 {
                                        prev.truncate(0);
                                        if encrypt {
                                            prev.extend_from_slice(&ct);
                                        } else {
                                            prev.extend_from_slice(&pt);
                                        }
                                    }

                                    let aes = <$aes>::new(&key);
                                    if encrypt {
                                        aes.encrypt_blocks(&mut pt);
                                        ct = pt.clone();
                                    } else {
                                        aes.decrypt_blocks(&mut ct);
                                        pt = ct.clone();
                                    }
                                }
                                let current = if encrypt {
                                    ct.as_flattened()
                                } else {
                                    pt.as_flattened()
                                };
                                key_shuffle(&mut key, current, prev.as_flattened());

                                if encrypt {
                                    assert_eq!(
                                        ct.as_flattened(),
                                        results_array[i].ct,
                                        "#{tc_id},{i}"
                                    );
                                } else {
                                    assert_eq!(
                                        pt.as_flattened(),
                                        results_array[i].pt,
                                        "#{tc_id},{i}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    };
}
pub(crate) use impl_acvp;

macro_rules! impl_test_aes {
    ($name:ident) => {
        #[derive(Clone, Debug)]
        enum $name {
            Aes128(Aes128),
            Aes192(Aes192),
            Aes256(Aes256),
        }
        impl $name {
            pub fn new(key: &[u8]) -> Self {
                match key.len() {
                    16 => Self::Aes128(Aes128::new(key.try_into().unwrap())),
                    24 => Self::Aes192(Aes192::new(key.try_into().unwrap())),
                    32 => Self::Aes256(Aes256::new(key.try_into().unwrap())),
                    n => panic!("invalid key length: {n}"),
                }
            }

            pub fn encrypt_block(&self, block: &mut Block) {
                match self {
                    Self::Aes128(aes) => aes.encrypt_block(block),
                    Self::Aes192(aes) => aes.encrypt_block(block),
                    Self::Aes256(aes) => aes.encrypt_block(block),
                }
            }

            pub fn encrypt_blocks(&self, blocks: &mut [Block]) {
                match self {
                    Self::Aes128(aes) => aes.encrypt_blocks(blocks),
                    Self::Aes192(aes) => aes.encrypt_blocks(blocks),
                    Self::Aes256(aes) => aes.encrypt_blocks(blocks),
                }
            }

            pub fn decrypt_block(&self, block: &mut Block) {
                match self {
                    Self::Aes128(aes) => aes.decrypt_block(block),
                    Self::Aes192(aes) => aes.decrypt_block(block),
                    Self::Aes256(aes) => aes.decrypt_block(block),
                }
            }

            pub fn decrypt_blocks(&self, blocks: &mut [Block]) {
                match self {
                    Self::Aes128(aes) => aes.decrypt_blocks(blocks),
                    Self::Aes192(aes) => aes.decrypt_blocks(blocks),
                    Self::Aes256(aes) => aes.decrypt_blocks(blocks),
                }
            }
        }
    };
}
pub(crate) use impl_test_aes;
