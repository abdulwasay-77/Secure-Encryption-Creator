# File Vault (AES-256-GCM)

Encrypt a sensitive file (e.g. passwords.txt) before uploading it, and decrypt it later.

## Setup
```
python -m venv venv
venv\Scripts\activate        # Windows   (Linux/macOS: source venv/bin/activate)
pip install -r requirements.txt
python generate_key.py       # ONCE: creates a random 256-bit key inside .env
```

## Use
```
python vault.py encrypt passwords.txt            # creates passwords.txt.enc
python vault.py encrypt passwords.txt --delete   # ...and removes the plaintext
python vault.py decrypt passwords.txt.enc        # restores passwords.txt
```

## Rules that keep it safe
1. **Back up `.env`** (it holds the key). Lose it = data is gone forever.
2. **Never upload `.env` together with the `.enc` file**, or the encryption is pointless.
   Store the key separately (e.g. a different cloud account, USB drive, or password manager).
3. `.env` and plaintext files are already listed in `.gitignore`.
4. Don't run `generate_key.py --force` unless you no longer need old encrypted files.
