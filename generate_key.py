"""Run this ONCE to create a random AES-256 key and store it in .env."""
import argparse
import base64
import os
import secrets
import sys
from pathlib import Path

ENV_PATH = Path(__file__).parent / ".env"


def read_current_key() -> str:
    if not ENV_PATH.exists():
        return ""
    for line in ENV_PATH.read_text().splitlines():
        if line.startswith("AES_KEY="):
            return line.split("=", 1)[1].strip()
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an AES-256 key into .env")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite an existing key (old encrypted files become UNREADABLE)")
    args = parser.parse_args()

    if read_current_key() and not args.force:
        sys.exit("A key already exists in .env. Refusing to overwrite it, because files "
                 "encrypted with it would be lost forever. Use --force only if you are sure.")

    key = base64.b64encode(secrets.token_bytes(32)).decode()  # 32 bytes = 256 bits

    lines = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    lines = [l for l in lines if not l.startswith("AES_KEY=")]
    lines.append(f"AES_KEY={key}")
    ENV_PATH.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(ENV_PATH, 0o600)  # owner-only on Linux/macOS
    except OSError:
        pass

    print("New AES-256 key saved to .env")
    print("IMPORTANT: back up .env somewhere safe and SEPARATE from the encrypted file.")
    print("If you lose this key, your encrypted data cannot be recovered.")


if __name__ == "__main__":
    main()
