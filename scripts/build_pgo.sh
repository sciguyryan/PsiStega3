#!/usr/bin/env bash
set -euo pipefail

# Path setup for script-relative paths.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PROFDIR="$SCRIPT_DIR/pgo-data"

echo "Cleaning old PGO data..."
rm -rf "$TMP_PROFDIR"

# Workspace-root paths (for things outside scripts/).
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_CRATE="psistega3-cli"
BINARY_PATH="$WORKSPACE_ROOT/target/release/$BINARY_CRATE"
PGO_BUILD_DIR="$WORKSPACE_ROOT/target/release-pgo"
PGO_BINARY_PATH="$PGO_BUILD_DIR/$BINARY_CRATE"
MERGED_PROFILE="$SCRIPT_DIR/merged.profdata"

# Step 0a - Prepare IMAGE_DIR.
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

# Step 0b - Prepare TEXT_DIR.
# Try both hyphenated and underscored names, like images.
if [[ -d "$SCRIPT_DIR/pgo-text-files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo-text-files"
elif [[ -d "$SCRIPT_DIR/pgo_text_files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo_text_files"
else
    echo "Error: No text folder found. Please create either:"
    echo "  $SCRIPT_DIR/pgo-text-files"
    echo "  $SCRIPT_DIR/pgo_text_files"
    echo " and populate them with sample PGO text files."
    exit 1
fi

# Gather text files
TEXT_FILES=("$TEXT_DIR"/*)
if [[ ${#TEXT_FILES[@]} -eq 0 ]]; then
    echo "Error: No text files found in $TEXT_DIR"
    exit 1
fi

# Workload config.
FIXED_PASSWORD="PGOSecretKey"
REPEAT_COUNT=10

# Step 0 - Prepare directories.
echo "=== Preparing build directories ==="
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
    for TEXT_FILE in "${TEXT_FILES[@]}"; do
        ITER_TEXT="$(< "$TEXT_FILE")"
        TEXT_NAME="$(basename "$TEXT_FILE" .txt)"

        for i in $(seq 1 "$REPEAT_COUNT"); do
            ENCODED_FILE="$SCRIPT_DIR/$(basename "$IMAGE_FILE").${TEXT_NAME}.encoded.$i.png"

            echo "Run $i/$REPEAT_COUNT: Encoding $IMAGE_FILE with contents of $TEXT_FILE"

            LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
                "$BINARY_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$ITER_TEXT" \
                -p "$FIXED_PASSWORD" --version v3 > /dev/null 2>&1 || {
                echo "Error: Encode failed for $IMAGE_FILE with contents of $TEXT_FILE"
                exit 1
            }

            echo "Run $i/$REPEAT_COUNT: Decoding $ENCODED_FILE"

            LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
                "$BINARY_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD" \
                > /dev/null 2>&1 || {
                echo "Error: Decode failed for $IMAGE_FILE with contents of $TEXT_FILE"
                exit 1
            }

            # Clean up.
            rm -f "$ENCODED_FILE"
        done
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

rm -rf "$TMP_PROFDIR"

echo "=== Done! PGO-optimized binary available at $PGO_BINARY_PATH ==="
