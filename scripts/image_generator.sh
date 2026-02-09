#!/usr/bin/env bash
set -euo pipefail

# PGO image generator for RGBA 32-bit PNGs.

IMG_DIR="./pgo-image-files"
mkdir -p "$IMG_DIR"

echo "Generating PGO training images in $IMG_DIR..."

# 1. Fully opaque flat color (low entropy).
magick -size 1024x1024 xc:"#808080ff" PNG32:"$IMG_DIR/flat_opaque.png"

# 2. Fully transparent (alpha-heavy).
magick -size 1024x1024 xc:"#00000000" PNG32:"$IMG_DIR/flat_transparent.png"

# 3. Smooth gradient RGB + soft alpha.
magick -size 1024x1024 gradient:black-white \
    -alpha set \
    -channel A -evaluate set 50% +channel \
    PNG32:"$IMG_DIR/gradient_soft_alpha.png"

# 4. Hard alpha edges (worst-case for alpha handling).
magick -size 1024x1024 xc:none \
    -fill "#ff0000ff" -draw "rectangle 0,0 511,1023" \
    -fill "#0000ffff" -draw "rectangle 512,0 1023,1023" \
    PNG32:"$IMG_DIR/hard_alpha_edges.png"

# 5. High-entropy procedural noise (plasma fractal).
magick -size 1024x1024 plasma:fractal \
    -alpha set \
    PNG32:"$IMG_DIR/plasma_rgba.png"

# 6. Odd dimensions with mixed alpha.
magick -size 124x6788 plasma:fractal \
    -alpha set \
    PNG32:"$IMG_DIR/odd_rgba.png"

# Large high-entropy RGBA PNG.
magick -size 4096x4096 plasma:fractal \
    -alpha set \
    -channel A -evaluate set 50% +channel \
    PNG32:"$IMG_DIR/huge_rgba.png"

echo "PGO images generated successfully!"
echo "Contents of $IMG_DIR:"
ls -lh "$IMG_DIR"
