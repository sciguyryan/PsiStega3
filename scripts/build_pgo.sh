#!/usr/bin/env bash
set -euo pipefail

# Path setup.
# Script-relative paths.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PROFDIR="$SCRIPT_DIR/pgo-data"

# Workspace-root paths (for things outside scripts/).
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_CRATE="psistega3-cli"
BINARY_PATH="$WORKSPACE_ROOT/target/release/$BINARY_CRATE"
PGO_BUILD_DIR="$WORKSPACE_ROOT/target/release-pgo"
PGO_BINARY_PATH="$PGO_BUILD_DIR/$BINARY_CRATE"
MERGED_PROFILE="$SCRIPT_DIR/merged.profdata"

# Step 0 - Prepare IMAGE_DIR.
# Try both hyphenated and underscored names, since either may be used.
if [[ -d "$SCRIPT_DIR/pgo-image-files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo-image-files"
elif [[ -d "$SCRIPT_DIR/pgo_image_files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo_image_files"
else
    echo "Error: No image folder found. Please create either:"
    echo "  $SCRIPT_DIR/pgo-image-files"
    echo "  $SCRIPT_DIR/pgo_image_files"
    echo " and populate them with the sample PGO image files."
    exit 1
fi

# Workload config.
LOREM_TEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc eu leo nec neque aliquet mollis at vel ligula. Etiam et enim orci. Fusce sit amet tincidunt libero. Curabitur pretium vestibulum risus et placerat. Vestibulum a pharetra mauris, eu efficitur tortor. Mauris suscipit metus sit amet purus laoreet, sed aliquet nibh vehicula. Proin ut purus nec magna fringilla tempus id eu magna. Ut hendrerit, dui eget euismod tristique, quam eros aliquet purus, vel pellentesque tellus urna quis mauris. Vivamus sed nibh consectetur, euismod ligula sed, molestie felis. Praesent ultrices felis vel nulla pulvinar, ut commodo eros volutpat. Maecenas tempor in eros nec bibendum."
FIXED_PASSWORD="PGOSecretKey"
REPEAT_COUNT=5

# Step 0 - Prepare directories.
echo "=== Preparing build directories ==="
mkdir -p "$TMP_PROFDIR"
rm -f "$MERGED_PROFILE"
rm -f "$TMP_PROFDIR"/*.profraw || true

# Step 1 - Build instrumented binary.
echo "=== Building instrumented binary (PGO instrumentation) ==="
export RUSTFLAGS="-C profile-generate=$TMP_PROFDIR"
cargo clean -p "$BINARY_CRATE"
# cargo build --release -p "$BINARY_CRATE"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: Instrumented binary not found at $BINARY_PATH"
    exit 1
fi

# Step 2 - Run instrumented binary for profile generation.
echo "=== Running instrumented binary for profile generation ==="
shopt -s nullglob
IMAGE_FILES=("$IMAGE_DIR"/*)
if [[ ${#IMAGE_FILES[@]} -eq 0 ]]; then
    echo "Error: No images found in $IMAGE_DIR"
    exit 1
fi

for IMAGE_FILE in "${IMAGE_FILES[@]}"; do
    for i in $(seq 1 "$REPEAT_COUNT"); do
        ENCODED_FILE="$SCRIPT_DIR/$(basename "$IMAGE_FILE").encoded.$i.png"
        ITER_TEXT="$LOREM_TEXT [Run $i]"

        echo "Run $i/$REPEAT_COUNT: Encoding $IMAGE_FILE"

        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$ITER_TEXT" -p "$FIXED_PASSWORD" --version v3

        echo "Run $i/$REPEAT_COUNT: Decoding $ENCODED_FILE"

        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD"

        rm -f "$ENCODED_FILE"
    done
done

# Step 3 - Merge profile data.
echo "=== Merging profile data ==="
PROFRAW_FILES=("$TMP_PROFDIR"/*.profraw)
if [[ ${#PROFRAW_FILES[@]} -eq 0 ]]; then
    echo "Error: No .profraw files found in $TMP_PROFDIR"
    exit 1
fi

llvm-profdata merge -o "$MERGED_PROFILE" "${PROFRAW_FILES[@]}"

# Step 4 - Build PGO-optimized release.
echo "=== Building PGO-optimized release ==="
mkdir -p "$PGO_BUILD_DIR"
export RUSTFLAGS="-C profile-use=$MERGED_PROFILE"
cargo build --release -p "$BINARY_CRATE" --target-dir "$PGO_BUILD_DIR"


rm -f "$TMP_PROFDIR"

echo "=== Done! PGO-optimized binary available at $PGO_BINARY_PATH ==="
