#!/usr/bin/env python3
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
import random
import string
import subprocess
from tabulate import tabulate
import tempfile
import time

# Config.
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
NORMAL_BINARY = WORKSPACE_ROOT / "target/release/psistega3-cli"
PGO_BINARY = WORKSPACE_ROOT / "target/release-pgo/release/psistega3-cli"
IMAGE_DIR = WORKSPACE_ROOT / "scripts/pgo-image-files"
TEXT_DIR = WORKSPACE_ROOT / "scripts/pgo-text-files"

REPEAT_COUNT = 10
RANDOM_TEXT_SIZE = 8192
FIXED_PASSWORD = "PGOSecretKey"

# Gather files.
images = list(IMAGE_DIR.glob("*"))
texts = list(TEXT_DIR.glob("*"))

if not images or not texts:
    raise RuntimeError("No images or text files found.")

# Helpers.
def generate_random_text(size):
    return ''.join(random.choices(string.ascii_letters + string.digits + " \n\t.,;:!?()[]{}", k=size))

def run_binary(binary, image_file, text_content):
    start = time.time()
    with tempfile.NamedTemporaryFile(suffix=".png", dir="/dev/shm") as tmp_file:
        encoded_path = tmp_file.name

        # Encode.
        subprocess.run(
            [str(binary), "--unattended", "encode",
             str(image_file), encoded_path, text_content,
             "-p", FIXED_PASSWORD, "--version", "v3"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True
        )

        # Decode.
        subprocess.run(
            [str(binary), "--unattended", "decode",
             str(image_file), encoded_path,
             "-p", FIXED_PASSWORD],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=True
        )
    return (time.time() - start) * 1000 # ms.

def clean_label(path: Path):
    """Return a simple stem, first part before underscore."""
    return path.stem.split("_")[0]

# Benchmark.
results = []

for image_file in images:
    for text_file in texts + [None]: # Add None for random text.
        if text_file:
            text_label = text_file.name
            text_content = text_file.read_text()
        else:
            text_label = "<random>"
            text_content = generate_random_text(RANDOM_TEXT_SIZE)

        normal_times = [run_binary(NORMAL_BINARY, image_file, text_content) for _ in range(REPEAT_COUNT)]
        pgo_times = [run_binary(PGO_BINARY, image_file, text_content) for _ in range(REPEAT_COUNT)]

        normal_avg = sum(normal_times)/len(normal_times)
        pgo_avg = sum(pgo_times)/len(pgo_times)
        delta = pgo_avg - normal_avg

        results.append({
            "image": image_file,
            "text": text_file if text_file else None,
            "normal_avg": normal_avg,
            "pgo_avg": pgo_avg,
            "delta": delta
        })

# Table output.
table_data = []
for r in results:
    image_label = clean_label(r["image"])
    text_label = "<random>" if r["text"] is None else clean_label(r["text"])
    delta_colored = f"{r['delta']:+.1f}"
    if r["delta"] < 0:
        delta_colored = f"\033[32m{delta_colored}\033[0m" # Green if PGO faster.
    elif r["delta"] > 0:
        delta_colored = f"\033[31m{delta_colored}\033[0m" # Red if PGO slower.
    table_data.append([text_label, image_label, round(r["normal_avg"],1), round(r["pgo_avg"],1), delta_colored])

print(tabulate(
    table_data,
    headers=["Text", "Image", "Normal Avg(ms)", "PGO Avg(ms)", "Delta(ms)"],
    tablefmt="plain"
))

# Graphical output.
labels = [f"{('<random>' if r['text'] is None else clean_label(r['text']))} | {clean_label(r['image'])}" for r in results]
normal_avgs = [r['normal_avg'] for r in results]
pgo_avgs = [r['pgo_avg'] for r in results]

x = np.arange(len(labels))
width = 0.35

fig, ax = plt.subplots(figsize=(12,6))
ax.bar(x - width/2, normal_avgs, width, label='Normal', color='skyblue')
ax.bar(x + width/2, pgo_avgs, width, label='PGO', color='orange')

ax.set_ylabel('Avg Time (ms)')
ax.set_title('Normal vs. PGO Benchmark')
ax.set_xticks(x)
ax.set_xticklabels(labels, rotation=90, ha='right')
ax.legend()
plt.tight_layout()
plt.show()
