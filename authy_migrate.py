#!/usr/bin/env python3
"""
Decrypt Authy GDPR export tokens and convert to standard authenticator formats.

Encryption scheme:
  Key  = PBKDF2-HMAC-SHA1(password, salt_utf8, iterations=100000, dklen=32)
  Data = AES-256-CBC(key, iv_hex, base64(encrypted_seed))
"""
import argparse
import base64
import binascii
import csv
import getpass
import hashlib
import io
import json
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

from Crypto.Cipher import AES


KDF_ITERATIONS = 100_000


def decrypt_seed(encrypted_seed_b64: str, salt: str, iv_hex: str, password: str) -> str:
    """Return base32-encoded TOTP secret (uppercase)."""
    key = hashlib.pbkdf2_hmac(
        "sha1",
        password.encode("utf-8"),
        salt.encode("utf-8"),  # salt is raw UTF-8, not base64
        KDF_ITERATIONS,
        dklen=32,
    )
    iv = bytes.fromhex(iv_hex)
    ciphertext = base64.b64decode(encrypted_seed_b64)
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)

    pad = plain[-1]
    if pad < 1 or pad > 16 or not all(b == pad for b in plain[-pad:]):
        raise ValueError("Invalid padding — wrong password?")

    return plain[:-pad].decode("utf-8").strip().upper()


def split_name(name_field: str) -> tuple[str, str]:
    """Split 'Service:account' into (issuer, account)."""
    issuer, _, account = name_field.partition(":")
    return issuer.strip(), account.strip()


def build_otpauth(issuer: str, account: str, secret: str) -> str:
    issuer_enc = quote(issuer, safe="")
    label = f"{issuer_enc}:{quote(account, safe='')}" if account else issuer_enc
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits=6&period=30"


def write_secret_file(path: Path, content: str) -> None:
    """Write file with owner-only (0600) permissions to avoid leaking secrets to other local users."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    # fchmod before writing closes the race window when the file pre-existed with looser perms:
    # os.open's mode arg is ignored on existing files, so the first write would otherwise
    # land while the file is still readable by others.
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def build_aegis(tokens: list[dict]) -> dict:
    return {
        "version": 1,
        "header": {"slots": None, "params": None},
        "db": {
            "version": 2,
            "entries": [
                {
                    "type": "totp",
                    "uuid": str(uuid.uuid4()),
                    "name": t["account"] or t["issuer"],
                    "issuer": t["issuer"],
                    "note": "",
                    "favorite": False,
                    "icon": None,
                    "info": {
                        "secret": t["secret"],
                        "algo": "SHA1",
                        "digits": 6,
                        "period": 30,
                    },
                }
                for t in tokens
            ],
        },
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Decrypt Authy GDPR export tokens into standard authenticator formats."
    )
    parser.add_argument(
        "input", type=Path, help="Path to the Authy GDPR export CSV file"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for output files (default: same directory as input)",
    )
    parser.add_argument(
        "-p",
        "--password",
        default=None,
        help=(
            "Backup password. UNSAFE: visible to other users via `ps` "
            "and stored in shell history. Omit to be prompted."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["aegis", "uris", "both"],
        default="both",
        help="Output format: aegis JSON, otpauth URI list, or both (default: both)",
    )
    parser.add_argument(
        "--aegis-file",
        default="tokens_aegis.json",
        metavar="NAME",
        help="Filename for the Aegis JSON export (default: tokens_aegis.json)",
    )
    parser.add_argument(
        "--uris-file",
        default="otpauth_uris.txt",
        metavar="NAME",
        help="Filename for the otpauth URI list (default: otpauth_uris.txt)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.input.exists():
        print(f"Error: {args.input} not found", file=sys.stderr)
        sys.exit(1)

    output_dir = args.output_dir or args.input.parent
    if not output_dir.is_dir():
        print(f"Error: output directory does not exist: {output_dir}", file=sys.stderr)
        sys.exit(1)

    password = args.password or getpass.getpass("Authy backup password: ")

    content = args.input.read_text(encoding="utf-8").strip()
    # Authy wraps the entire CSV in a single pair of quotes, which causes
    # Python's csv parser to treat the whole file as one quoted field.
    if content.startswith('"') and content.endswith('"'):
        content = content[1:-1]

    reader = csv.DictReader(io.StringIO(content))
    required = {"name", "encrypted_seed", "salt", "iv"}
    missing = required - set(reader.fieldnames or [])
    if missing:
        print(
            f"Error: CSV is missing required columns: {sorted(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    successes = []
    failures = []
    rows_attempted = 0

    for row in reader:
        name = row["name"].strip()
        enc_seed = row["encrypted_seed"].strip()
        salt = row["salt"].strip()
        iv = row["iv"].strip()

        if not name or not enc_seed:
            continue
        rows_attempted += 1

        try:
            secret = decrypt_seed(enc_seed, salt, iv, password)
            issuer, account = split_name(name)
            successes.append(
                {"name": name, "issuer": issuer, "account": account, "secret": secret}
            )
            print(f"  ✓  {name}")
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            failures.append((name, exc))
            print(f"  ✗  {name}: {exc}")

    if rows_attempted == 0:
        print("\nNo valid token rows found in CSV.", file=sys.stderr)
        sys.exit(1)
    if not successes:
        print("\nNo tokens decrypted — wrong backup password?", file=sys.stderr)
        sys.exit(1)

    written = []

    if args.format in ("aegis", "both"):
        aegis_path = output_dir / args.aegis_file
        write_secret_file(aegis_path, json.dumps(build_aegis(successes), indent=2))
        written.append(aegis_path)

    if args.format in ("uris", "both"):
        uris_path = output_dir / args.uris_file
        uris = "".join(
            build_otpauth(t["issuer"], t["account"], t["secret"]) + "\n"
            for t in successes
        )
        write_secret_file(uris_path, uris)
        written.append(uris_path)

    print(
        f"\nDecrypted {len(successes)} token(s)"
        + (f", {len(failures)} failed" if failures else "")
    )
    print("\nOutput:")
    for path in written:
        print(f"  {path}")
    print("\n⚠  Delete these files after importing — they contain plaintext secrets.")


if __name__ == "__main__":
    main()
