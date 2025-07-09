#!/usr/bin/env python3
"""
Console app to extract all .exe files from archives in a directory, check them against malicious hashes, and keep only safe .exe files.
"""
import os
import zipfile
import tarfile
import rarfile
import hashlib
import requests
import pickle
from pathlib import Path
from typing import Set
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MALICIOUS_HASH_URLS = {
    'md5': "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-md5-aa.txt",
    'sha1': "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha1-aa.txt",
    'sha256': "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/main/full-hash-sha256-aa.txt"
}

CACHE_FILE = ".malicious_hash_cache"


def load_malicious_hashes() -> dict:
    """Download and cache malicious hashes."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'rb') as f:
            return pickle.load(f)
    hashes = {'md5': set(), 'sha1': set(), 'sha256': set()}
    for hash_type, url in MALICIOUS_HASH_URLS.items():
        logger.info(f"Downloading {hash_type} hashes...")
        try:
            resp = requests.get(url, timeout=60)
            if resp.status_code == 200:
                hashes[hash_type] = set(h.strip().lower() for h in resp.text.splitlines() if h.strip())
        except Exception as e:
            logger.error(f"Error downloading {hash_type} hashes: {e}")
    with open(CACHE_FILE, 'wb') as f:
        pickle.dump(hashes, f)
    return hashes

def calculate_hashes(file_path: Path) -> dict:
    """Calculate MD5, SHA1, SHA256 for a file."""
    hashes = {}
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest().lower()
            hashes['sha1'] = hashlib.sha1(content).hexdigest().lower()
            hashes['sha256'] = hashlib.sha256(content).hexdigest().lower()
    except Exception as e:
        logger.error(f"Error calculating hashes for {file_path}: {e}")
    return hashes

def is_safe_file(file_path: Path, malicious_hashes: dict) -> bool:
    file_hashes = calculate_hashes(file_path)
    for hash_type, file_hash in file_hashes.items():
        if file_hash in malicious_hashes[hash_type]:
            logger.warning(f"Malicious file detected: {file_path} ({hash_type}: {file_hash})")
            return False
    return True

def extract_exes_from_archive(archive_path: Path, output_dir: Path, malicious_hashes: dict) -> int:
    extracted = 0
    try:
        if archive_path.suffix.lower() == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                for member in zip_ref.namelist():
                    if member.endswith('.exe'):
                        out_path = output_dir / f"{archive_path.stem}_{os.path.basename(member)}"
                        with open(out_path, 'wb') as f:
                            f.write(zip_ref.read(member))
                        if is_safe_file(out_path, malicious_hashes):
                            logger.info(f"Extracted: {out_path}")
                            extracted += 1
                        else:
                            out_path.unlink()
        elif archive_path.suffix.lower() in ['.tar', '.gz'] or '.tar.gz' in archive_path.name:
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                for member in tar_ref.getnames():
                    if member.endswith('.exe'):
                        out_path = output_dir / f"{archive_path.stem}_{os.path.basename(member)}"
                        with open(out_path, 'wb') as f:
                            f.write(tar_ref.extractfile(member).read())
                        if is_safe_file(out_path, malicious_hashes):
                            logger.info(f"Extracted: {out_path}")
                            extracted += 1
                        else:
                            out_path.unlink()
        elif archive_path.suffix.lower() == '.rar':
            with rarfile.RarFile(archive_path) as rar_ref:
                for member in rar_ref.namelist():
                    if member.endswith('.exe'):
                        out_path = output_dir / f"{archive_path.stem}_{os.path.basename(member)}"
                        with open(out_path, 'wb') as f:
                            f.write(rar_ref.read(member))
                        if is_safe_file(out_path, malicious_hashes):
                            logger.info(f"Extracted: {out_path}")
                            extracted += 1
                        else:
                            out_path.unlink()
    except Exception as e:
        logger.error(f"Error extracting from {archive_path}: {e}")
    return extracted

def clean_directory(directory: Path, malicious_hashes: dict):
    """Remove all non-.exe files and malicious .exe files from directory."""
    for file in directory.iterdir():
        if file.is_file():
            if file.suffix.lower() == '.exe':
                if not is_safe_file(file, malicious_hashes):
                    logger.warning(f"Deleting malicious exe: {file}")
                    file.unlink()
            else:
                logger.info(f"Deleting non-exe: {file}")
                file.unlink()

def menu():
    print("\n==== EXE Extractor & Cleaner ====")
    print("1. Extract .exe from all archives in this folder")
    print("2. Clean this folder (remove non-exe and malicious exe)")
    print("3. Download/refresh malicious hash lists")
    print("4. Exit")
    return input("Choose an option: ")

def main():
    malicious_hashes = load_malicious_hashes()
    while True:
        choice = menu()
        if choice == '1':
            folder = input("Enter folder with archives (default: current): ").strip() or os.getcwd()
            output = input("Enter output folder for exes (default: same as above): ").strip() or folder
            folder = Path(folder)
            output = Path(output)
            output.mkdir(exist_ok=True)
            print(f"Extracting .exe from archives in: {folder}")
            count = 0
            for file in folder.iterdir():
                if file.suffix.lower() in ['.zip', '.tar', '.gz', '.rar'] or '.tar.gz' in file.name:
                    logger.info(f"Extracting from {file}")
                    count += extract_exes_from_archive(file, output, malicious_hashes)
            print(f"Total .exe extracted: {count}")
        elif choice == '2':
            folder = input("Enter folder to clean (default: current): ").strip() or os.getcwd()
            folder = Path(folder)
            print(f"Cleaning directory: {folder}")
            clean_directory(folder, malicious_hashes)
            print("Directory cleaned.")
        elif choice == '3':
            print("Refreshing hash lists...")
            if os.path.exists(CACHE_FILE):
                os.remove(CACHE_FILE)
            malicious_hashes = load_malicious_hashes()
            print("Hash lists refreshed.")
        elif choice == '4':
            print("Bye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
