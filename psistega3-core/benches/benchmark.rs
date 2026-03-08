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

                        let mut stega = StegaV3::new();
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

fn benchmark_v3_decoding_compression(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoding_v3_compression");

    let test_configs = [
        ("medium", get_sample_file_path("ref_medium.png")),
        ("large", get_sample_file_path("ref_large.png")),
    ];

    let compression_options = [(true, "compressed"), (false, "uncompressed")];

    group.sample_size(15);
    group.measurement_time(Duration::from_secs(180));
    group.warm_up_time(Duration::from_secs(10));

    let key = "we're benchmarking!!!".to_string();
    let input = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque diam tortor, ultrices quis augue eu, semper congue justo. Sed pharetra dui nec magna dignissim, sit amet placerat sem elementum. Pellentesque in purus sed risus tincidunt ultrices at id dui. Aenean vitae lacinia nisl. Donec tortor ante, vehicula non hendrerit nec, hendrerit eget mi. Aliquam erat volutpat. Nullam blandit dui dui. Phasellus a iaculis quam, quis egestas ex. In non porttitor nisi, vitae tempor lorem. Maecenas sed elit eu tortor tincidunt euismod.\nMorbi tincidunt felis ut purus tempus dapibus. Donec quis scelerisque velit. Maecenas placerat, turpis eget malesuada placerat, nunc mauris consectetur turpis, a aliquam eros leo eu nibh. Curabitur fermentum metus vel turpis vestibulum luctus. Ut egestas finibus enim, nec rhoncus dolor sodales eu. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras fringilla at nisi dictum mattis. Quisque id congue nisl, ut commodo lorem. Morbi aliquam vel quam sed aliquet. Etiam gravida diam eget rhoncus porttitor.\nFusce blandit id mi imperdiet placerat. Suspendisse eu arcu non orci commodo interdum ut quis lectus. Maecenas turpis enim, ullamcorper nec enim quis, semper pharetra erat. Morbi augue augue, bibendum et ornare viverra, rhoncus a sem. Vivamus ut diam aliquam, molestie neque nec, sollicitudin tortor. Curabitur vehicula magna eu ante pulvinar malesuada. Pellentesque ultricies egestas dignissim. Aliquam lorem lectus, sagittis hendrerit felis vitae, lacinia tempor elit. In semper ullamcorper est. Curabitur auctor eros in enim convallis accumsan sit amet et sapien. Etiam pharetra lectus volutpat arcu maximus sollicitudin. Maecenas gravida efficitur dolor, vitae tempus neque. Donec dignissim vel nunc a maximus. Integer egestas congue magna, non auctor lectus ornare malesuada.";

    for (name, img_path) in test_configs.iter() {
        for (use_compression, suffix) in compression_options.iter() {
            let benchmark_name = format!("{name}_{suffix}");
            group.bench_with_input(
                BenchmarkId::from_parameter(&benchmark_name),
                &(img_path, *use_compression),
                |b, (img_path, use_compression)| {
                    b.iter_batched(
                        || {
                            let output_path = get_temp_output_path();

                            let mut stega = StegaV3::new();
                            stega.set_flag_state(ConfigFlags::DisableCompression, !state);
                            stega
                                .encode(img_path, key.clone(), input, &output_path)
                                .expect("encode failed");

                            (output_path, stega)
                        },
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
    benchmark_v3_decoding_compression,
);
criterion_main!(benches);
