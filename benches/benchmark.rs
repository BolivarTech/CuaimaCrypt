//! Benchmarks for CuaimaCrypt cipher operations.
//!
//! Measures password initialization, single-block codec/decodec throughput,
//! and codec throughput scaling across different rake counts.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use cuaimacrypt::CuaimaCrypt;

/// Password used consistently across all benchmarks.
const BENCH_PASSWORD: &str = "BenchmarkPassword2024";

/// Block size in bytes (128-bit block = 16 bytes).
const BLOCK_SIZE_BYTES: u64 = 16;

/// Benchmarks `CuaimaCrypt::password()` initialization time.
///
/// Measures the full key-derivation path including PasswordSparker
/// construction, KAOSrand seeding, and state distribution across
/// all ShiftCodecs.
fn bench_password_init(c: &mut Criterion) {
    c.bench_function("password_init", |b| {
        b.iter(|| {
            let mut cc = CuaimaCrypt::new();
            cc.password(black_box(BENCH_PASSWORD)).unwrap();
        });
    });
}

/// Benchmarks single-block `codec()` throughput with the default 9 rakes.
///
/// Each iteration encrypts one 128-bit block. The cipher is initialized
/// once and state advances naturally between iterations, reflecting
/// real-world streaming behavior.
fn bench_codec(c: &mut Criterion) {
    let mut cc = CuaimaCrypt::new();
    cc.password(BENCH_PASSWORD).unwrap();

    let mut group = c.benchmark_group("codec_single_block");
    group.throughput(Throughput::Bytes(BLOCK_SIZE_BYTES));

    group.bench_function("9_rakes", |b| {
        let mut block: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
        b.iter(|| {
            cc.codec(black_box(&mut block));
        });
    });

    group.finish();
}

/// Benchmarks single-block `decodec()` throughput with the default 9 rakes.
///
/// Each iteration decrypts one 128-bit block. The cipher is initialized
/// once and state advances naturally between iterations.
fn bench_decodec(c: &mut Criterion) {
    let mut cc = CuaimaCrypt::new();
    cc.password(BENCH_PASSWORD).unwrap();

    let mut group = c.benchmark_group("decodec_single_block");
    group.throughput(Throughput::Bytes(BLOCK_SIZE_BYTES));

    group.bench_function("9_rakes", |b| {
        let mut block: [i64; 2] = [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
        b.iter(|| {
            cc.decodec(black_box(&mut block));
        });
    });

    group.finish();
}

/// Benchmarks `codec()` throughput across different rake counts.
///
/// Compares encryption cost with 2, 9, and 16 RakeCodecs to show
/// how security scaling (more rakes) affects per-block performance.
fn bench_codec_rake_scaling(c: &mut Criterion) {
    let rake_counts: &[usize] = &[2, 9, 16];

    let mut group = c.benchmark_group("codec_rake_scaling");
    group.throughput(Throughput::Bytes(BLOCK_SIZE_BYTES));

    for &num_rakes in rake_counts {
        let mut cc = CuaimaCrypt::with_num_rakes(num_rakes).unwrap();
        cc.password(BENCH_PASSWORD).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(num_rakes),
            &num_rakes,
            |b, _| {
                let mut block: [i64; 2] =
                    [0x0123456789ABCDEF_u64 as i64, 0xFEDCBA9876543210_u64 as i64];
                b.iter(|| {
                    cc.codec(black_box(&mut block));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_password_init,
    bench_codec,
    bench_decodec,
    bench_codec_rake_scaling,
);
criterion_main!(benches);
