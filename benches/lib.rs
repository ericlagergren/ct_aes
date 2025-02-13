//! Benchmarks.

#![allow(missing_docs)]

use core::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use ct_aes::{aes32, aes64, Block, BLOCK_SIZE};

macro_rules! bench_aes32 {
    ($name:ident, $aes:ty) => {
        fn $name(c: &mut Criterion) {
            let mut g = c.benchmark_group(stringify!($name));

            g.throughput(Throughput::Elements(1))
                .bench_function("new", |b| {
                    let key = [0u8; <$aes>::KEY_SIZE];
                    b.iter(|| {
                        black_box(<$aes>::new(black_box(&key)));
                    });
                });

            g.throughput(Throughput::Bytes(BLOCK_SIZE as u64))
                .bench_function("encrypt_block", |b| {
                    let mut aes = <$aes>::new(&[0u8; <$aes>::KEY_SIZE]);
                    let mut block = Block::default();
                    b.iter(|| black_box(&mut aes).encrypt_block(black_box(&mut block)));
                    black_box(&block);
                });

            g.throughput(Throughput::Bytes(2 * BLOCK_SIZE as u64))
                .bench_function("encrypt_blocks", |b| {
                    let mut aes = <$aes>::new(&[0u8; <$aes>::KEY_SIZE]);
                    let mut block1 = Block::default();
                    let mut block2 = Block::default();
                    b.iter(|| {
                        black_box(&mut aes)
                            .encrypt_blocks(black_box(&mut block1), black_box(&mut block2))
                    });
                    black_box(&block1);
                    black_box(&block2);
                });

            g.finish();
        }
    };
}
bench_aes32!(bench_aes128_32, aes32::Aes128);
bench_aes32!(bench_aes192_32, aes32::Aes192);
bench_aes32!(bench_aes256_32, aes32::Aes256);

macro_rules! bench_aes64 {
    ($name:ident, $aes:ty) => {
        fn $name(c: &mut Criterion) {
            let mut g = c.benchmark_group(stringify!($name));

            g.throughput(Throughput::Elements(1))
                .bench_function("new", |b| {
                    let key = [0u8; <$aes>::KEY_SIZE];
                    b.iter(|| {
                        black_box(<$aes>::new(black_box(&key)));
                    });
                });

            g.throughput(Throughput::Bytes(BLOCK_SIZE as u64))
                .bench_function("encrypt_block", |b| {
                    let mut aes = <$aes>::new(&[0u8; <$aes>::KEY_SIZE]);
                    let mut block = [0u8; <$aes>::BLOCK_SIZE];
                    b.iter(|| black_box(&mut aes).encrypt_block(black_box(&mut block)));
                    black_box(&block);
                });

            g.throughput(Throughput::Bytes(4 * BLOCK_SIZE as u64))
                .bench_function("encrypt_blocks", |b| {
                    let mut aes = <$aes>::new(&[0u8; <$aes>::KEY_SIZE]);
                    let mut block1 = Block::default();
                    let mut block2 = Block::default();
                    let mut block3 = Block::default();
                    let mut block4 = Block::default();
                    b.iter(|| {
                        black_box(&mut aes).encrypt_blocks(
                            black_box(&mut block1),
                            black_box(&mut block2),
                            black_box(&mut block3),
                            black_box(&mut block4),
                        )
                    });
                    black_box(&block1);
                    black_box(&block2);
                    black_box(&block3);
                    black_box(&block4);
                });

            g.finish();
        }
    };
}
bench_aes64!(bench_aes128_64, aes64::Aes128);
bench_aes64!(bench_aes192_64, aes64::Aes192);
bench_aes64!(bench_aes256_64, aes64::Aes256);

fn benchmarks(c: &mut Criterion) {
    bench_aes128_32(c);
    bench_aes192_32(c);
    bench_aes256_32(c);

    bench_aes128_64(c);
    bench_aes192_64(c);
    bench_aes256_64(c);
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
