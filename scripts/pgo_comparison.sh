#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

NORMAL_BINARY="$WORKSPACE_ROOT/target/release/psistega3-cli"
PGO_BINARY="$WORKSPACE_ROOT/target/release-pgo/release/psistega3-cli"

# Flags
SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --skip-builds) SKIP_BUILD=true ;;
    esac
done

# Directories
if [[ -d "$SCRIPT_DIR/pgo-image-files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo-image-files"
elif [[ -d "$SCRIPT_DIR/pgo_image_files" ]]; then
    IMAGE_DIR="$SCRIPT_DIR/pgo_image_files"
else
    echo "Error: No image folder found."
    exit 1
fi

if [[ -d "$SCRIPT_DIR/pgo-text-files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo-text-files"
elif [[ -d "$SCRIPT_DIR/pgo_text_files" ]]; then
    TEXT_DIR="$SCRIPT_DIR/pgo_text_files"
else
    echo "Error: No text folder found."
    exit 1
fi

shopt -s nullglob
IMAGE_FILES=("$IMAGE_DIR"/*)
TEXT_FILES=("$TEXT_DIR"/*)

[[ ${#IMAGE_FILES[@]} -gt 0 && ${#TEXT_FILES[@]} -gt 0 ]] || {
    echo "Error: Missing image or text files."
    exit 1
}

# Config
FIXED_PASSWORD="PGOSecretKey"
REPEAT_COUNT=10
RANDOM_TEXT_SIZE=8192

# Global associative arrays
declare -A NORMAL_AVG_MAP
declare -A PGO_AVG_MAP

# PGO summary accumulators
PGO_WINS=0
PGO_LOSSES=0
PGO_NEUTRAL=0
PGO_BEST=-999
PGO_WORST=999
PGO_SUM_PCT=0
PGO_COUNT=0

# Build step
if [[ "$SKIP_BUILD" == false ]]; then
    echo "=== Building normal release ==="
    cargo build --release
    echo "=== Building PGO release ==="
    "$WORKSPACE_ROOT/scripts/build_pgo.sh"
else
    echo "=== Skipping builds (--skip-builds) ==="
    [[ -x "$NORMAL_BINARY" ]] || { echo "Normal binary not found"; exit 1; }
    [[ -x "$PGO_BINARY" ]] || { echo "PGO binary not found"; exit 1; }
fi

# Random text generator
generate_random_text() {
    dd if=/dev/urandom bs=1 count="$RANDOM_TEXT_SIZE" status=none \
        | tr -dc 'a-zA-Z0-9 \n\t.,;:!?()[]{}'
}

run_case() {
    local BIN_PATH="$1"
    local TYPE="$2"
    local IMAGE_FILE="$3"
    local IMAGE_NAME="$4"
    local TEXT_LABEL="$5"
    local TEXT_CONTENT="$6"

    local TIMES=()
    local TOTAL=0

    local COLOR_RESET=$'\e[0m'
    local COLOR_GREEN=$'\e[32m'
    local COLOR_RED=$'\e[31m'

    for i in $(seq 1 "$REPEAT_COUNT"); do
        local SAFE_LABEL="${TEXT_LABEL//[^a-zA-Z0-9]/_}"
        local ENCODED_FILE="$SCRIPT_DIR/${IMAGE_NAME}.${SAFE_LABEL}.encoded.$i.png"

        local START END MS
        START=$(date +%s%N)
        "$BIN_PATH" --unattended encode "$IMAGE_FILE" "$ENCODED_FILE" "$TEXT_CONTENT" \
            -p "$FIXED_PASSWORD" --version v3 > /dev/null 2>&1
        "$BIN_PATH" --unattended decode "$IMAGE_FILE" "$ENCODED_FILE" -p "$FIXED_PASSWORD" \
            > /dev/null 2>&1
        END=$(date +%s%N)

        MS=$(((END - START)/1000000))
        TIMES+=("$MS")
        TOTAL=$((TOTAL + MS))

        rm -f "$ENCODED_FILE"
    done

    local COUNT=${#TIMES[@]}
    local AVG=$((TOTAL / COUNT))
    local MIN=${TIMES[0]}
    local MAX=${TIMES[0]}
    for t in "${TIMES[@]}"; do
        (( t < MIN )) && MIN=$t
        (( t > MAX )) && MAX=$t
    done

    local DELTA="-"
    if [[ "$TYPE" == "normal" ]]; then
        NORMAL_AVG_MAP["$IMAGE_NAME|$TEXT_LABEL"]="$AVG"
    else
        local NORMAL_AVG=${NORMAL_AVG_MAP["$IMAGE_NAME|$TEXT_LABEL"]}
        if [[ -n "$NORMAL_AVG" ]]; then
            local DIFF=$((AVG - NORMAL_AVG))
            if (( DIFF < 0 )); then
                DELTA="${COLOR_GREEN}${DIFF}${COLOR_RESET}"
            elif (( DIFF > 0 )); then
                DELTA="${COLOR_RED}+${DIFF}${COLOR_RESET}"
            else
                DELTA="${DIFF}"
            fi
        fi
    fi

    printf "%-28s %-28s %-6d %-10d %-10d %-10d %b\n" \
        "$IMAGE_NAME" "$TEXT_LABEL" "$COUNT" "$AVG" "$MIN" "$MAX" "$DELTA"
}

benchmark_binary() {
    local BIN_PATH="$1"
    local LABEL="$2"

    echo
    echo "=== Benchmarking $LABEL ==="
    printf "%-28s %-28s %-6s %-10s %-10s %-10s %-10s\n" \
        "Image" "Text Source" "Runs" "Avg(ms)" "Min" "Max" "Avg Delta (ms)"
    printf "%s\n" "----------------------------------------------------------------------------------------------------------"

    local TYPE="normal"
    [[ "$LABEL" != "Normal Release" ]] && TYPE="pgo"

    for IMAGE_FILE in "${IMAGE_FILES[@]}"; do
        local IMAGE_NAME="$(basename "$IMAGE_FILE")"

        # File-based tests
        for TEXT_FILE in "${TEXT_FILES[@]}"; do
            local TEXT_NAME="$(basename "$TEXT_FILE")"
            local TEXT_CONTENT="$(< "$TEXT_FILE")"
            run_case "$BIN_PATH" "$TYPE" "$IMAGE_FILE" "$IMAGE_NAME" "$TEXT_NAME" "$TEXT_CONTENT"
        done

        # Random test
        local RANDOM_TEXT
        RANDOM_TEXT="$(generate_random_text)"
        run_case "$BIN_PATH" "$TYPE" "$IMAGE_FILE" "$IMAGE_NAME" "<random>" "$RANDOM_TEXT"
    done
}

# Run benchmarks
benchmark_binary "$NORMAL_BINARY" "Normal Release"
benchmark_binary "$PGO_BINARY" "PGO Release"
