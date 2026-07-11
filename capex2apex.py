#!/usr/bin/env python3
"""
capex2apex.py

Extracts the embedded original_apex from Android .capex files.

Usage:
    python capex2apex.py myfile.capex
    python capex2apex.py path/to/folder
"""

from pathlib import Path
import zipfile
import shutil
import argparse
import sys


def extract_capex(capex_path: Path):
    output = capex_path.with_suffix(".apex")

    try:
        with zipfile.ZipFile(capex_path, "r") as z:
            if "original_apex" not in z.namelist():
                print(f"[!] {capex_path.name}: original_apex not found")
                return False

            with z.open("original_apex") as src, output.open("wb") as dst:
                shutil.copyfileobj(src, dst)

        print(f"[OK] {capex_path.name} -> {output.name}")
        return True

    except zipfile.BadZipFile:
        print(f"[!] {capex_path.name}: Not a valid CAPEX file")
    except Exception as e:
        print(f"[!] {capex_path.name}: {e}")

    return False


def process(path: Path):
    if path.is_file():
        if path.suffix.lower() != ".capex":
            print("Input file is not a .capex")
            return
        extract_capex(path)
        return

    if path.is_dir():
        capex_files = sorted(path.rglob("*.capex"))

        if not capex_files:
            print("No .capex files found.")
            return

        success = 0

        for f in capex_files:
            if extract_capex(f):
                success += 1

        print()
        print(f"Converted {success}/{len(capex_files)} CAPEX files.")
        return

    print("Invalid path.")


def main():
    parser = argparse.ArgumentParser(
        description="Extract original_apex from Android CAPEX files."
    )
    parser.add_argument("input", help="CAPEX file or directory")

    args = parser.parse_args()

    process(Path(args.input))


if __name__ == "__main__":
    main()
