#!/bin/bash
set -e

OUT_DIR="./generated"
SIZE="32x32"

# --- BMP ---
BMP_DIR="$OUT_DIR/bmp"
mkdir -p $BMP_DIR
magick -size $SIZE gradient: -depth 8 "$BMP_DIR/test_l8_ref.bmp"
magick -size $SIZE gradient: -depth 8 -alpha on "$BMP_DIR/test_la8_ref.bmp"
magick -size $SIZE gradient: -depth 16 "$BMP_DIR/test_l16_ref.bmp"
magick -size $SIZE gradient: -depth 16 -alpha on "$BMP_DIR/test_la16_ref.bmp"

# --- PNG ---
PNG_DIR="$OUT_DIR/png"
mkdir -p $PNG_DIR
magick -size $SIZE gradient: -depth 8 "$PNG_DIR/test_l8_ref.png"
magick -size $SIZE gradient: -depth 8 -alpha on "$PNG_DIR/test_la8_ref.png"
magick -size $SIZE gradient: -depth 16 "$PNG_DIR/test_l16_ref.png"
magick -size $SIZE gradient: -depth 16 -alpha on "$PNG_DIR/test_la16_ref.png"

# --- TIFF (32F for floating point) ---
TIFF_DIR="$OUT_DIR/tiff"
mkdir -p $TIFF_DIR
magick -size $SIZE gradient: -depth 32 "$TIFF_DIR/test_l32f_ref.tiff"
magick -size $SIZE gradient: -depth 32 -alpha on "$TIFF_DIR/test_la32f_ref.tiff"

# --- WebP (lossless only) ---
WEBP_DIR="$OUT_DIR/webp"
mkdir -p $WEBP_DIR
magick -size $SIZE gradient: -depth 8 -define webp:lossless=true "$WEBP_DIR/test_l8_ref.webp"
magick -size $SIZE gradient: -depth 8 -alpha on -define webp:lossless=true "$WEBP_DIR/test_la8_ref.webp"
magick -size $SIZE gradient: -depth 16 -define webp:lossless=true "$WEBP_DIR/test_l16_ref.webp"
magick -size $SIZE gradient: -depth 16 -alpha on -define webp:lossless=true "$WEBP_DIR/test_la16_ref.webp"

echo "All simple black and white gradients (BMP, PNG, TIFF, WebP) generated in $OUT_DIR."
