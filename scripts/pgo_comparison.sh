#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

NORMAL_BINARY="$WORKSPACE_ROOT/target/release/psistega3-cli"
PGO_BINARY="$WORKSPACE_ROOT/target/release-pgo/release/psistega3-cli"

LOREM_TEXT="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc eu leo nec neque aliquet mollis at vel ligula. Etiam et enim orci. Fusce sit amet tincidunt libero. Curabitur pretium vestibulum risus et placerat. Vestibulum a pharetra mauris, eu efficitur tortor. Mauris suscipit metus sit amet purus laoreet, sed aliquet nibh vehicula. Proin ut purus nec magna fringilla tempus id eu magna. Ut hendrerit, dui eget euismod tristique, quam eros aliquet purus, vel pellentesque tellus urna quis mauris. Vivamus sed nibh consectetur, euismod ligula sed, molestie felis. Praesent ultrices felis vel nulla pulvinar, ut commodo eros volutpat. Maecenas tempor in eros nec bibendum."
FIXED_PASSWORD="PGOSecretKey"
REPEAT_COUNT=20

# Step 0 - Prepare IMAGE_DIR.
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

# Populate IMAGE_FILES array.
shopt -s nullglob
IMAGE_FILES=("$IMAGE_DIR"/*)
if [[ ${#IMAGE_FILES[@]} -eq 0 ]]; then
    echo "Error: No images found in $IMAGE_DIR"
    exit 1
fi

# Step 1 - Build normal release
echo "=== Building normal release ==="
cargo build --release

# Step 2 - Build PGO release.
echo "=== Building PGO release ==="
"$WORKSPACE_ROOT/scripts/build_pgo.sh"

# Function to time encode/decode cycle.
function benchmark_binary() {
    local BIN_PATH="$1"
    local LABEL="$2"

    echo "=== Benchmarking $LABEL ==="

    TOTAL_TIME=0
    TIMES=()

    for IMAGE_FILE in "${IMAGE_FILES[@]}"; do
        for i in $(seq 1 $REPEAT_COUNT); do
            ENCODED_FILE="$SCRIPT_DIR/$(basename "$IMAGE_FILE").encoded.$i.png"
            ITER_TEXT="$LOREM_TEXT [Run $i]"

            START=$(date +%s%N)

            "$BIN_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$ITER_TEXT" -p "$FIXED_PASSWORD" --version v3 > /dev/null 2>&1
            "$BIN_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD" > /dev/null 2>&1

            END=$(date +%s%N)
            DURATION=$((END - START))
            # Convert nanoseconds to milliseconds.
            DURATION_MS=$((DURATION / 1000000))
            TIMES+=($DURATION_MS)
            TOTAL_TIME=$((TOTAL_TIME + DURATION_MS))

            rm -f "$ENCODED_FILE"
        done
    done

    COUNT=${#TIMES[@]}
    AVG=$((TOTAL_TIME / COUNT))

    MIN=${TIMES[0]}
    MAX=${TIMES[0]}
    for t in "${TIMES[@]}"; do
        (( t < MIN )) && MIN=$t
        (( t > MAX )) && MAX=$t
    done

    echo "Results for $LABEL (ms per encode+decode):"
    echo "  Runs : $COUNT"
    echo "  Avg  : $AVG"
    echo "  Min  : $MIN"
    echo "  Max  : $MAX"
    echo
}

# Step 3 - Run benchmarks.
benchmark_binary "$NORMAL_BINARY" "Normal Release"
benchmark_binary "$PGO_BINARY" "PGO Release"
