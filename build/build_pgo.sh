#!/usr/bin/env bash
set -euo pipefail

# Workspace-relative paths.
WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_DIR="$WORKSPACE_ROOT/build/pgo_image_files"
BUILD_DIR="$WORKSPACE_ROOT/build"
TMP_PROFDIR="$BUILD_DIR/pgo_data"
MERGED_PROFILE="$BUILD_DIR/merged.profdata"
BINARY_CRATE="psistega3-cli"
BINARY_PATH="$WORKSPACE_ROOT/target/release/$BINARY_CRATE"

# Workload config.
LOREM_TEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit. PGO test run."
FIXED_PASSWORD="PGOSecretKey"
REPEAT_COUNT=5

# Step 0 - Prepare directories.
echo "=== Preparing build directories ==="
mkdir -p "$BUILD_DIR"
mkdir -p "$TMP_PROFDIR"
rm -f "$MERGED_PROFILE"
rm -f "$TMP_PROFDIR"/*.profraw || true

# Step 1 - Build instrumented binary.
echo "=== Building instrumented binary (PGO instrumentation) ==="
export RUSTFLAGS="-C profile-generate=$TMP_PROFDIR"
cargo clean -p "$BINARY_CRATE"
cargo build --release -p "$BINARY_CRATE"

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
    for i in $(seq 1 $REPEAT_COUNT); do
        ENCODED_FILE="$BUILD_DIR/$(basename "$IMAGE_FILE").encoded.$i.png"
        ITER_TEXT="$LOREM_TEXT [Run $i]"

        echo "Run $i/$REPEAT_COUNT: Encoding $IMAGE_FILE"

        # Encode text into the image.
        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$ITER_TEXT" -p "$FIXED_PASSWORD" --version v3

        echo "Run $i/$REPEAT_COUNT: Decoding $ENCODED_FILE"

        # Decode the data again.
        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD"

        # Clean up intermediate files
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
export RUSTFLAGS="-C profile-use=$MERGED_PROFILE"
cargo build --release -p "$BINARY_CRATE"

echo "=== Done! PGO-optimized binary available at $BINARY_PATH ==="
