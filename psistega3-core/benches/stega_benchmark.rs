use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use psistega3_core::codecs::{codec::Codec, v2::StegaV2};
use std::{env, hint::black_box, time::Duration};

fn benchmark_v2_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("encoding");

    // Get absolute paths to reference images
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let test_configs = [
        (
            "tiny",
            format!("{manifest_dir}/benches/reference_images/ref_tiny.png"),
        ),
        (
            "small",
            format!("{manifest_dir}/benches/reference_images/ref_small.png"),
        ),
        (
            "medium",
            format!("{manifest_dir}/benches/reference_images/ref_medium.png"),
        ),
        (
            "large",
            format!("{manifest_dir}/benches/reference_images/ref_large.png"),
        ),
        (
            "checkerboard",
            format!("{manifest_dir}/benches/reference_images/ref_checkerboard.png"),
        ),
        (
            "noise",
            format!("{manifest_dir}/benches/reference_images/ref_noise.png"),
        ),
    ];

    // More meaningful timings for slow cryptographic operations.
    group.sample_size(10); // Fewer samples for long-running operations.
    group.measurement_time(Duration::from_secs(60)); // 1 minute per benchmark.
    group.warm_up_time(Duration::from_secs(10)); // 10 second warmup

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
                        black_box("we're benchmarking!!!".to_string()),
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

/*fn benchmark_v2_decoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding");

    // Similar structure for decoding...
    for size in [1_024, 10_240, 102_400].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}KB", size / 1024)),
            size,
            |b, &size| {
                let (ref_img, enc_img) = setup_encoded_images(size);
                let mut stega = StegaV2::new("password");

                b.iter(|| {
                    stega.decode(
                        black_box(&ref_img),
                        black_box(&enc_img)
                    )
                });
            }
        );
    }
    group.finish();
}

fn benchmark_v2_read_u8(c: &mut Criterion) {
    // Micro-benchmark for the specific optimization
    let ref_img = setup_reference_image();
    let enc_img = setup_encoded_image();
    let stega = StegaV2::new("password");

    c.bench_function("read_u8", |b| {
        b.iter(|| {
            for i in 0..1000 {
                black_box(stega.read_u8(
                    black_box(&ref_img),
                    black_box(&enc_img),
                    black_box(i * 8)
                ));
            }
        });
    });
}

fn benchmark_v2_scramble(c: &mut Criterion) {
    let mut group = c.benchmark_group("scramble");
    group.measurement_time(Duration::from_secs(10)); // Longer for accuracy

    c.bench_function("scramble_1920x1080", |b| {
        b.iter_batched(
            || setup_1920x1080_image(),
            |mut img| img.scramble(),    // Benchmark this
            criterion::BatchSize::SmallInput
        );
    });

    group.finish();
}*/

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
    //benchmark_v2_decoding,
    //benchmark_v2_read_u8,
    //benchmark_v2_scramble
);
criterion_main!(benches);
