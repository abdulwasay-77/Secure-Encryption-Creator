"""Encrypt / decrypt a file with AES-256-GCM.

Usage:
    python vault.py encrypt passwords.txt          -> passwords.txt.enc
    python vault.py decrypt passwords.txt.enc      -> passwords.txt
Options: --out PATH to choose output file, --force to overwrite, --delete to
remove the original after a successful operation.
"""
import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

MAGIC = b"VLT1"      # file header / format version (also authenticated)
NONCE_SIZE = 12       # recommended nonce size for GCM


def load_key() -> bytes:
    load_dotenv(Path(__file__).parent / ".env")
    raw = os.getenv("AES_KEY", "").strip()
    if not raw:
        sys.exit("No AES_KEY found in .env. Run: python generate_key.py")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        sys.exit("AES_KEY in .env is not valid base64.")
    if len(key) != 32:
        sys.exit("AES_KEY must decode to exactly 32 bytes (AES-256).")
    return key


def encrypt_file(src: Path, dst: Path) -> None:
    nonce = os.urandom(NONCE_SIZE)  # fresh random nonce for every encryption
    ct = AESGCM(load_key()).encrypt(nonce, src.read_bytes(), MAGIC)
    dst.write_bytes(MAGIC + nonce + ct)


def decrypt_file(src: Path, dst: Path) -> None:
    blob = src.read_bytes()
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + NONCE_SIZE + 16:
        sys.exit("This does not look like a file encrypted by this tool.")
    nonce = blob[len(MAGIC):len(MAGIC) + NONCE_SIZE]
    ct = blob[len(MAGIC) + NONCE_SIZE:]
    try:
        pt = AESGCM(load_key()).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        sys.exit("Decryption failed: wrong key, or the file was corrupted/tampered with.")
    dst.write_bytes(pt)


def main() -> None:
    p = argparse.ArgumentParser(description="AES-256-GCM file vault")
    p.add_argument("action", choices=["encrypt", "decrypt"])
    p.add_argument("file", type=Path)
    p.add_argument("--out", type=Path, help="output path")
    p.add_argument("--force", action="store_true", help="overwrite output if it exists")
    p.add_argument("--delete", action="store_true", help="delete the input file afterwards")
    a = p.parse_args()

    if not a.file.is_file():
        sys.exit(f"File not found: {a.file}")

    if a.out:
        out = a.out
    elif a.action == "encrypt":
        out = a.file.with_name(a.file.name + ".enc")
    else:
        out = a.file.with_suffix("") if a.file.suffix == ".enc" else a.file.with_name(a.file.name + ".dec")

    if out.exists() and not a.force:
        sys.exit(f"{out} already exists. Use --force to overwrite.")

    (encrypt_file if a.action == "encrypt" else decrypt_file)(a.file, out)
    print(f"{a.action.capitalize()}ed: {a.file} -> {out}")

    if a.delete:
        a.file.unlink()
        print(f"Deleted: {a.file}")


if __name__ == "__main__":
    main()
