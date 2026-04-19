import argparse
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--version", required=True)
args = parser.parse_args()

confirm = input("This will generate test images and undo existing static file tests. Continue? [y/N]: ")
if confirm.lower() not in ("y", "yes"):
    print("Aborted.")
    exit(1)

BASE_DIR = Path(f"./assets/encoding_decoding_{args.version}/format_tests")
SIZE = "32x32"
CLI = Path("../target/release/psistega3-cli.exe")
INPUT = "3.1415926535"
KEY = "ElPsyKongroo"

BASE_DIR.mkdir(parents=True, exist_ok=True)

COMBOS = [
    ("bmp","L8",8,0), ("bmp","Rgb8",8,0), ("bmp","Rgba8",8,1),
#    ("farbfeld","Rgba16",16,1),
    ("png","L8",8,0), ("png","La8",8,1),
    ("png","L16",16,0), ("png","La16",16,1),
    ("png","Rgb8",8,0), ("png","Rgba8",8,1),
    ("png","Rgb16",16,0), ("png","Rgba16",16,1),
    ("tiff","L8",8,0), ("tiff","L16",16,0),
    ("tiff","Rgb8",8,0), ("tiff","Rgba8",8,1),
    ("tiff","Rgb16",16,0), ("tiff","Rgba16",16,1),
    ("tiff","Rgb32F",32,0), ("tiff","Rgba32F",32,1),
    ("webp","L8",8,0), ("webp","La8",8,1),
    ("webp","Rgb8",8,0), ("webp","Rgba8",8,1),
]

def run(cmd):
    subprocess.run(cmd, check=True)

for fmt, typ, depth, alpha in COMBOS:
    ext = "ff" if fmt == "farbfeld" else fmt
    dir_path = BASE_DIR / ext
    dir_path.mkdir(exist_ok=True)

    ref = dir_path / f"test_{typ.lower()}_ref.{ext}"
    enc = dir_path / f"test_{typ.lower()}_encoded.{ext}"

    if fmt == "bmp":
        pix = {"L8":"gray","Rgb8":"bgr24","Rgba8":"bgra"}.get(typ)
        if not pix:
            print(f"Skipping BMP {typ}")
            continue

        run(["ffmpeg","-f","lavfi","-i",f"color=black:s={SIZE}",
             "-frames:v","1","-pix_fmt",pix,str(ref),"-y","-loglevel","quiet"])
    else:
        args_magick = ["magick","-size",SIZE,"-depth",str(depth)]

        if fmt == "webp":
            args_magick += ["-define","webp:lossless=true"]

        if fmt == "tiff":
            args_magick += ["-compress","none","-define","tiff:planarconfig=contig"]
            if depth in (8,16):
                args_magick += ["-define","quantum:format=unsigned"]
            elif depth == 32:
                args_magick += ["-define","quantum:format=float"]

        args_magick += ["xc:black"]

        type_map = {
            "Rgb8":"TrueColor", "Rgb16":"TrueColor",
            "Rgba8":"TrueColorAlpha", "Rgba16":"TrueColorAlpha"
        }

        if typ in type_map:
            args_magick += ["-type", type_map[typ]]
        elif typ in ("Rgb32F","Rgba32F"):
            args_magick += ["-depth","32","-define","quantum:format=float"]
            args_magick += ["-type","TrueColorAlpha" if "A" in typ else "TrueColor"]
        elif typ.startswith("La"):
            args_magick += ["-alpha","on"]

        args_magick.append(str(ref))
        run(args_magick)

    print(f"Generated {ref}")

    run([
        str(CLI), "encode", str(ref), str(enc), INPUT,
        "-p", KEY, "-v", args.version,
        "--t-cost","1","--p-cost","1","--m-cost","4000","--use-compression","false","--unattended"
    ])

    print(f"Generated encoded {enc}")
    print("-------------")

print("All done.")
