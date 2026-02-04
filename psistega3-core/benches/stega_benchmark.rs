use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use psistega3_core::codecs::{
    codec::Codec,
    {v2::StegaV2, v3::StegaV3},
};
use std::{env, hint::black_box, time::Duration};

fn benchmark_v2_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding_v2");

    let test_configs = [
        ("tiny", get_sample_file_path("ref_tiny.png")),
        ("small", get_sample_file_path("ref_small.png")),
        ("medium", get_sample_file_path("ref_medium.png")),
        ("large", get_sample_file_path("ref_large.png")),
        ("checkerboard", get_sample_file_path("ref_checkerboard.png")),
        ("noise", get_sample_file_path("ref_noise.png")),
    ];

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(10));

    let key = "we're benchmarking!!!".to_string();
    let mut stega = StegaV2::new("benchmark");

    for (name, img_path) in test_configs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            img_path,
            |b, img_path| {
                let output_path = get_temp_output_path();
                b.iter(|| {
                    stega.encode(
                        black_box(img_path),
                        black_box(key.clone()),
                        black_box("It's a fez. I wear a fez now, fezzes are cool."),
                        black_box(&output_path),
                    )
                });

                // Cleanup after all iterations.
                std::fs::remove_file(&output_path).ok();
            },
        );
    }
    group.finish();
}

fn benchmark_v2_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding_v2");

    let test_configs = [
        ("tiny", get_sample_file_path("ref_tiny.png")),
        ("small", get_sample_file_path("ref_small.png")),
        ("medium", get_sample_file_path("ref_medium.png")),
        ("large", get_sample_file_path("ref_large.png")),
    ];

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(10));

    let key = "we're benchmarking!!!".to_string();

    for (name, img_path) in test_configs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            img_path,
            |b, img_path| {
                b.iter_batched(
                    // Setup, not measured.
                    || {
                        let output_path = get_temp_output_path();

                        let mut stega = StegaV2::new("benchmark");
                        stega
                            .encode(
                                img_path,
                                key.clone(),
                                "It's a fez. I wear a fez now, fezzes are cool.",
                                &output_path,
                            )
                            .expect("encode failed");

                        (output_path, stega)
                    },
                    // Measured.
                    |(output_path, mut stega)| {
                        stega.decode(
                            black_box(&img_path),
                            black_box(key.clone()),
                            black_box(&output_path),
                        )
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn benchmark_v3_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding_v3");

    let test_configs = [
        ("tiny", get_sample_file_path("ref_tiny.png")),
        ("small", get_sample_file_path("ref_small.png")),
        ("medium", get_sample_file_path("ref_medium.png")),
        ("large", get_sample_file_path("ref_large.png")),
        ("checkerboard", get_sample_file_path("ref_checkerboard.png")),
        ("noise", get_sample_file_path("ref_noise.png")),
    ];

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(10));

    let key = "we're benchmarking!!!".to_string();
    let mut stega = StegaV3::new();

    for (name, img_path) in test_configs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            img_path,
            |b, img_path| {
                let output_path = get_temp_output_path();
                b.iter(|| {
                    stega.encode(
                        black_box(img_path),
                        black_box(key.clone()),
                        black_box("It's a fez. I wear a fez now, fezzes are cool."),
                        black_box(&output_path),
                    )
                });

                // Cleanup after all iterations.
                std::fs::remove_file(&output_path).ok();
            },
        );
    }
    group.finish();
}

fn benchmark_v3_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding_v3");

    let test_configs = [
        ("tiny", get_sample_file_path("ref_tiny.png")),
        ("small", get_sample_file_path("ref_small.png")),
        ("medium", get_sample_file_path("ref_medium.png")),
        ("large", get_sample_file_path("ref_large.png")),
    ];

    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));
    group.warm_up_time(Duration::from_secs(10));

    let key = "we're benchmarking!!!".to_string();

    for (name, img_path) in test_configs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            img_path,
            |b, img_path| {
                b.iter_batched(
                    // Setup, not measured.
                    || {
                        let output_path = get_temp_output_path();

                        let mut stega = StegaV2::new("benchmark");
                        stega
                            .encode(
                                img_path,
                                key.clone(),
                                "It's a fez. I wear a fez now, fezzes are cool.",
                                &output_path,
                            )
                            .expect("encode failed");

                        (output_path, stega)
                    },
                    // Measured.
                    |(output_path, mut stega)| {
                        stega.decode(
                            black_box(&img_path),
                            black_box(key.clone()),
                            black_box(&output_path),
                        )
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }

    group.finish();
}

fn benchmark_v3_generate_junk_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("junk_bytes_v3");

    for size in [1_000usize, 10_000, 100_000, 1_000_000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| black_box(StegaV3::generate_junk_bytes(size)));
        });
    }

    group.finish();
}

fn get_sample_file_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    format!("{manifest_dir}/benches/reference_images/{name}")
}

fn get_temp_output_path() -> String {
    // Use /dev/shm (RAM disk) on Linux if available.
    if cfg!(target_os = "linux") && std::path::Path::new("/dev/shm").exists() {
        format!("/dev/shm/bench_output_{}.png", std::process::id())
    }
    // Use /tmp on macOS, which is usually backed by a RAM disk.
    else if cfg!(target_os = "macos") {
        format!("/tmp/bench_output_{}.png", std::process::id())
    }
    // Fallback to system temp for Windows and OSs that don't have a RAM disk.
    else {
        let mut path = env::temp_dir();
        path.push(format!("bench_output_{}.png", std::process::id()));
        path.to_string_lossy().to_string()
    }
}

criterion_group!(
    benches,
    benchmark_v2_encoding,
    benchmark_v2_decoding,
    benchmark_v3_encoding,
    benchmark_v3_decoding,
    benchmark_v3_generate_junk_bytes,
);
criterion_main!(benches);
