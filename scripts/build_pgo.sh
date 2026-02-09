#!/usr/bin/env bash
set -euo pipefail

# ========================================== #
# PGO Training Script with Weighted Proportions
# ========================================== #

# Script-relative paths.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_PROFDIR="$SCRIPT_DIR/pgo-data"

echo "Cleaning old PGO data..."
rm -rf "$TMP_PROFDIR"

# Workspace-root paths.
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY_CRATE="psistega3-cli"
BINARY_PATH="$WORKSPACE_ROOT/target/release/$BINARY_CRATE"
PGO_BUILD_DIR="$WORKSPACE_ROOT/target/release-pgo"
PGO_BINARY_PATH="$PGO_BUILD_DIR/$BINARY_CRATE"
MERGED_PROFILE="$SCRIPT_DIR/merged.profdata"

# Step 0a - Prepare IMAGE_DIR
if [[ -d "$SCRIPT_DIR/pgo-image-files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo-image-files"
elif [[ -d "$SCRIPT_DIR/pgo_image_files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo_image_files"
else
    echo "Error: No image folder found. Please create either:"
    echo "  $SCRIPT_DIR/pgo-image-files"
    echo "  $SCRIPT_DIR/pgo_image_files"
    exit 1
fi

# Step 0b - Prepare TEXT_DIR
if [[ -d "$SCRIPT_DIR/pgo-text-files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo-text-files"
elif [[ -d "$SCRIPT_DIR/pgo_text_files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo_text_files"
else
    echo "Error: No text folder found. Please create either:"
    echo "  $SCRIPT_DIR/pgo-text-files"
    echo "  $SCRIPT_DIR/pgo_text_files"
    exit 1
fi

# Gather files
IMAGE_FILES=("$IMAGE_DIR"/*)
TEXT_FILES=("$TEXT_DIR"/*)
if [[ ${#IMAGE_FILES[@]} -eq 0 ]]; then
    echo "Error: No images found in $IMAGE_DIR"
    exit 1
fi
if [[ ${#TEXT_FILES[@]} -eq 0 ]]; then
    echo "Error: No text files found in $TEXT_DIR"
    exit 1
fi

# Workload config
FIXED_PASSWORD="PGOSecretKey"
TOTAL_RUNS=1000  # Total PGO cycles across all pairs

# Helper function to parse weight from filenames
get_weight() {
    local fname="$1"
    if [[ "$fname" =~ _w([0-9]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo 1  # default weight
    fi
}

# Step 1 - Prepare directories
echo "=== Preparing build directories ==="
mkdir -p "$TMP_PROFDIR"
rm -f "$MERGED_PROFILE"
rm -f "$TMP_PROFDIR"/*.profraw || true

# Step 2 - Build instrumented binary
echo "=== Building instrumented binary (PGO instrumentation) ==="
export RUSTFLAGS="-C profile-generate=$TMP_PROFDIR"
cargo clean -p "$BINARY_CRATE"
cargo build --release -p "$BINARY_CRATE"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: Instrumented binary not found at $BINARY_PATH"
    exit 1
fi

# Step 3 - Compute total weight for proportional allocation
declare -A PAIR_WEIGHTS
TOTAL_WEIGHT=0
for IMAGE_FILE in "${IMAGE_FILES[@]}"; do
    IMAGE_WEIGHT=$(get_weight "$(basename "$IMAGE_FILE")")
    for TEXT_FILE in "${TEXT_FILES[@]}"; do
        TEXT_WEIGHT=$(get_weight "$(basename "$TEXT_FILE")")
        PAIR_KEY="${IMAGE_FILE}||${TEXT_FILE}"
        PAIR_WEIGHT=$(( IMAGE_WEIGHT * TEXT_WEIGHT ))
        PAIR_WEIGHTS["$PAIR_KEY"]=$PAIR_WEIGHT
        TOTAL_WEIGHT=$(( TOTAL_WEIGHT + PAIR_WEIGHT ))
    done
done

# Step 4 - Run instrumented binary for profile generation
echo "=== Running instrumented binary for profile generation ==="
shopt -s nullglob

ENCODE_TMP_DIR="/dev/shm/pgo-encoded"
mkdir -p "$ENCODE_TMP_DIR"

for PAIR_KEY in "${!PAIR_WEIGHTS[@]}"; do
    IMAGE_FILE="${PAIR_KEY%%||*}"
    TEXT_FILE="${PAIR_KEY##*||}"
    IMAGE_BASENAME="$(basename "$IMAGE_FILE")"
    TEXT_BASENAME="$(basename "$TEXT_FILE")"
    ITER_TEXT="$(< "$TEXT_FILE")"

    PAIR_WEIGHT="${PAIR_WEIGHTS[$PAIR_KEY]}"
    RUNS=$(( PAIR_WEIGHT * TOTAL_RUNS / TOTAL_WEIGHT ))
    RUNS=$(( RUNS > 0 ? RUNS : 1 ))  # ensure at least 1 run
    if [[ $RUNS -lt 1 ]]; then
        echo "Warning: Weighted runs for $IMAGE_FILE / $TEXT_FILE computed as 0. Forcing 1 run, increasing the total number of runs will help."
        RUNS=1
    fi

    for i in $(seq 1 "$RUNS"); do
        ENCODED_FILE="$ENCODE_TMP_DIR/${IMAGE_BASENAME}.${TEXT_BASENAME}.encoded.$i.png"

        echo "Run $i/$RUNS: Encoding $IMAGE_FILE with contents of $TEXT_FILE"

        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$ITER_TEXT" \
            -p "$FIXED_PASSWORD" --version v3 > /dev/null 2>&1 || {
                echo "Error: Encode failed for $IMAGE_FILE with contents of $TEXT_FILE"
                exit 1
            }

        echo "Run $i/$RUNS: Decoding $ENCODED_FILE"

        LLVM_PROFILE_FILE="$TMP_PROFDIR/%p.profraw" \
            "$BINARY_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD" \
            > /dev/null 2>&1 || {
                echo "Error: Decode failed for $IMAGE_FILE with contents of $TEXT_FILE"
                exit 1
            }

        rm -f "$ENCODED_FILE"
    done
done

# Step 5 - Merge profile data
echo "=== Merging profile data ==="
PROFRAW_FILES=("$TMP_PROFDIR"/*.profraw)
if [[ ${#PROFRAW_FILES[@]} -eq 0 ]]; then
    echo "Error: No .profraw files found in $TMP_PROFDIR"
    exit 1
fi

llvm-profdata merge -o "$MERGED_PROFILE" "${PROFRAW_FILES[@]}"

# Step 6 - Build PGO-optimized release
echo "=== Building PGO-optimized release ==="
mkdir -p "$PGO_BUILD_DIR"
export RUSTFLAGS="-C profile-use=$MERGED_PROFILE"
cargo build --release -p "$BINARY_CRATE" --target-dir "$PGO_BUILD_DIR"

# Cleanup.
rm -rf "$TMP_PROFDIR"

echo "=== Done! PGO-optimized binary available at $PGO_BINARY_PATH ==="
