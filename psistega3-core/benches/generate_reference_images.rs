//! Generate reference PNG images for benchmarking steganography operations.
//!
//! Run with: cargo run --features bench --bin generate_reference_images

use image::{ImageBuffer, Rgba, RgbaImage};
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("Generating reference images for benchmarks...\n");

    // Create the reference_images directory if it doesn't exist.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let output_dir = manifest_dir.join("benches").join("reference_images");
    fs::create_dir_all(&output_dir).expect("Failed to create benches/reference_images directory");

    // Define image configurations: (filename, width, height, pattern).
    let configs = [
        ("ref_tiny.png", 320, 240, ImagePattern::Gradient),
        ("ref_small.png", 640, 480, ImagePattern::Gradient),
        ("ref_medium.png", 1920, 1080, ImagePattern::Gradient),
        ("ref_large.png", 3840, 2160, ImagePattern::Gradient),
        (
            "ref_checkerboard.png",
            1920,
            1080,
            ImagePattern::Checkerboard,
        ),
        ("ref_noise.png", 1920, 1080, ImagePattern::Noise),
    ];

    for (filename, width, height, pattern) in configs.iter() {
        let path = output_dir.join(filename);
        print!("  Generating {} ({}x{})... ", filename, width, height);

        let img = generate_image(*width, *height, pattern);

        // Save using image crate's save method.
        img.save(&path)
            .expect(&format!("Failed to save {}", filename));

        // Get file size.
        let metadata = fs::metadata(&path).unwrap();
        let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
        println!("({:.2} MB)", size_mb);
    }

    println!("\nAll reference images generated successfully!");
    println!("Location: benches/reference_images/");
}

enum ImagePattern {
    Gradient,
    Checkerboard,
    Noise,
}

fn generate_image(width: u32, height: u32, pattern: &ImagePattern) -> RgbaImage {
    match pattern {
        ImagePattern::Gradient => generate_gradient(width, height),
        ImagePattern::Checkerboard => generate_checkerboard(width, height),
        ImagePattern::Noise => generate_noise(width, height),
    }
}

/// Generate a smooth gradient pattern using image crate.
fn generate_gradient(width: u32, height: u32) -> RgbaImage {
    ImageBuffer::from_fn(width, height, |x, y| {
        let r = ((x as f32 / width as f32) * 255.0) as u8;
        let g = ((y as f32 / height as f32) * 255.0) as u8;
        let b = ((x.wrapping_add(y) as f32 / (width + height) as f32) * 255.0) as u8;
        Rgba([r, g, b, 255])
    })
}

/// Generate a checkerboard pattern using image crate.
fn generate_checkerboard(width: u32, height: u32) -> RgbaImage {
    ImageBuffer::from_fn(width, height, |x, y| {
        let checker_size = 64;
        let is_dark = ((x / checker_size) + (y / checker_size)) % 2 == 0;

        if is_dark {
            Rgba([40, 40, 45, 255])
        } else {
            Rgba([220, 220, 225, 255])
        }
    })
}

/// Generate deterministic noise pattern using image crate.
fn generate_noise(width: u32, height: u32) -> RgbaImage {
    ImageBuffer::from_fn(width, height, |x, y| {
        // Deterministic hash based on position.
        let hash = x
            .wrapping_mul(2654435761)
            .wrapping_add(y.wrapping_mul(2246822519))
            .wrapping_add(12345);

        let r = (hash & 0xFF) as u8;
        let g = ((hash >> 8) & 0xFF) as u8;
        let b = ((hash >> 16) & 0xFF) as u8;

        Rgba([r, g, b, 255])
    })
}
