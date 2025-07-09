#!/usr/bin/env python3
"""
Checks all files in a folder for valid PE format using pefile. If valid, moves to /nice, else to /bad.
"""
import os
import shutil
from pathlib import Path
import pefile
import concurrent.futures

SRC_DIR = input("Enter folder to check (default: ./clean): ").strip() or "./clean"
NICE_DIR = "./nice"
BAD_DIR = "./bad"

os.makedirs(NICE_DIR, exist_ok=True)
os.makedirs(BAD_DIR, exist_ok=True)

files = [f for f in os.listdir(SRC_DIR) if os.path.isfile(os.path.join(SRC_DIR, f))]

def process_file(filename):
    file_path = os.path.join(SRC_DIR, filename)
    try:
        pe = pefile.PE(file_path, fast_load=True)
        # If no exception, it's a valid PE file
        shutil.move(file_path, os.path.join(NICE_DIR, filename))
        print(f"[NICE] {filename}")
    except pefile.PEFormatError:
        shutil.move(file_path, os.path.join(BAD_DIR, filename))
        print(f"[BAD]  {filename}")
    except Exception as e:
        print(f"[ERROR] {filename}: {e}")

with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as executor:
    executor.map(process_file, files)
