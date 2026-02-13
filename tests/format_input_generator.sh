#!/bin/bash
set -e

# Parse arguments.
VERSION=""
while getopts "v:" opt; do
  case $opt in
    v)
      VERSION="$OPTARG"
      ;;
    *)
      echo "Usage: $0 -v <version>"
      exit 1
      ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "Error: Version (-v) is required"
  exit 1
fi

read -rp "This will generate test images and therefore undo any of the existing static file tests. This should only be done when absolutely needed. Continue? [y/N]: " confirm

case "$confirm" in
  [yY]|[yY][eE][sS])
    echo "Continuing..."
    ;;
  *)
    echo "Aborted."
    exit 1
    ;;
esac

# Paths and constants.
BASE_DIR="./assets/encoding_decoding_${VERSION}/format_tests"
SIZE="32x32"

CLI_PATH="../target/release/psistega3-cli"
INPUT_TEXT="3.1415926535"
KEY="ElPsyKongroo"

mkdir -p "$BASE_DIR"

# Valid format/colour combos.
COMBOS=(
  "farbfeld:Rgba16:16:1"

  "png:L8:8:0"
  "png:La8:8:1"
  "png:L16:16:0"
  "png:La16:16:1"
  "png:Rgb8:8:0"
  "png:Rgba8:8:1"
  "png:Rgb16:16:0"
  "png:Rgba16:16:1"

  "tiff:L8:8:0"
  "tiff:L16:16:0"
  "tiff:Rgb8:8:0"
  "tiff:Rgba8:8:1"
  "tiff:Rgb16:16:0"
  "tiff:Rgba16:16:1"
  "tiff:Rgb32F:32:0"
  "tiff:Rgba32F:32:1"

  "webp:L8:8:0"
  "webp:La8:8:1"
  "webp:Rgb8:8:0"
  "webp:Rgba8:8:1"
)

echo "Generating reference and encoded images in $BASE_DIR..."

for combo in "${COMBOS[@]}"; do
  IFS=":" read -r fmt type depth alpha <<< "$combo"

  EXT="$fmt"
  if [ "$fmt" == "farbfeld" ]; then
    EXT="ff"
  fi

  DIR="$BASE_DIR/$EXT"
  mkdir -p "$DIR"

  REF_FILE="${DIR}/test_${type}_ref.${EXT}"; REF_FILE="${REF_FILE,,}"
  ENC_FILE="${DIR}/test_${type}_encoded.${EXT}"; ENC_FILE="${ENC_FILE,,}"

  # Base arguments
  ARGS="-size $SIZE -depth $depth"

  # WebP - must use lossless.
  if [ "$fmt" == "webp" ]; then
    ARGS="$ARGS -define webp:lossless=true"
  fi

  # TIFF specifics, these can be a bit weird.
  if [ "$fmt" == "tiff" ]; then
    ARGS="$ARGS -compress none -define tiff:planarconfig=contig"
    if [ "$depth" -eq 8 ] || [ "$depth" -eq 16 ]; then
      ARGS="$ARGS -define quantum:format=unsigned"
    elif [ "$depth" -eq 32 ]; then
      ARGS="$ARGS -define quantum:format=float"
    fi
  fi

  # Generate a blank reference image.
  case "$type" in
    L8|L16|Rgb8|Rgb16)
      TYPE_ARG=""
      if [[ "$type" == Rgb8 || "$type" == Rgb16 ]]; then
        TYPE_ARG="-type TrueColor"
      fi
      magick $ARGS xc:black $TYPE_ARG "$REF_FILE"
      ;;
    Rgba8|Rgba16)
      magick $ARGS xc:black -type TrueColorAlpha "$REF_FILE"
      ;;
    Rgb32F)
      magick $ARGS xc:black -type TrueColor -depth 32 -define quantum:format=float "$REF_FILE"
      ;;
    Rgba32F)
      magick $ARGS xc:black -type TrueColorAlpha -depth 32 -define quantum:format=float "$REF_FILE"
      ;;
    La8|La16)
      if [[ "$fmt" == "png" || "$fmt" == "webp" ]]; then
        magick $ARGS xc:black -alpha on "$REF_FILE"
      else
        echo "Skipping unsupported type $type for $fmt"
        continue
      fi
      ;;
    *)
      echo "Skipping unsupported type $type"
      continue
      ;;
  esac

  echo "Generated $REF_FILE"

  # Generate encoded image.
  $CLI_PATH encode "$REF_FILE" "$ENC_FILE" "$INPUT_TEXT" -p "$KEY" -v $VERSION --t-cost 1 --p-cost 1 --m-cost 4000 --unattended
  echo "Generated encoded $ENC_FILE"
  echo "-------------"
done

echo "All reference and encoded images generated for version $VERSION."
