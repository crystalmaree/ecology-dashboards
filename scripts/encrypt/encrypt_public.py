#!/usr/bin/env python3
"""
Encrypt all HTML files in public-encrypted/ using StatiCrypt,
output the protected files to public/ (the GitHub Pages release folder).

Password strategy: derived passwords
  Each file's password = HMAC-SHA256(master_secret, relative_path), base64-encoded.
  - One master secret to rule them all (store in your password manager)
  - Each file gets a unique password — sharing one doesn't expose others
  - Deterministic: you can always regenerate any password from secret + filename
  - The secret never touches the repo

Usage:
    python3 scripts/encrypt/encrypt_public.py                    # encrypt all files → public/
    python3 scripts/encrypt/encrypt_public.py --show             # show passwords without encrypting
    python3 scripts/encrypt/encrypt_public.py --skip-unchanged    # skip files whose encrypted output is newer than source
    python3 scripts/encrypt/encrypt_public.py --file reports/q1.html # one file only

Requirements:
    npx (Node.js) — StatiCrypt is run via npx, no global install needed.
"""

import argparse
import base64
import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path

WORKSPACE = Path(__file__).parent.parent.parent

# Load .env from workspace root if present (pure stdlib, no dependencies)
_env_file = WORKSPACE / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

SOURCE_DIR = WORKSPACE / "public-encrypted"
OUTPUT_DIR = WORKSPACE / "public"
TEMPLATE   = Path(__file__).parent / "template.html"


def derive_password(master_secret: str, relative_path: str) -> str:
    key = master_secret.encode("utf-8")
    msg = relative_path.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)[:24].decode("ascii")


def encrypt_file(src: Path, output_dir: Path, password: str) -> bool:
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "npx", "--yes", "staticrypt",
        str(src),
        "--password", password,
        "-d", str(output_dir),
        "--short",
    ]
    if TEMPLATE.exists():
        cmd += ["--template", str(TEMPLATE)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    staticrypt error: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def print_password_table(passwords: dict, results: dict = None):
    print()
    print(f"  {'File':<45} Password")
    print(f"  {'-'*45} {'-'*24}")
    for name, pwd in passwords.items():
        status = f"  [{results[name]}]" if results else ""
        print(f"  {name:<45} {pwd}{status}")
    print()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--skip-unchanged", action="store_true")
    parser.add_argument("--file", metavar="FILENAME")
    args = parser.parse_args()

    master_secret = os.environ.get("ENCRYPT_SECRET", "")
    if not master_secret:
        print("ERROR: ENCRYPT_SECRET environment variable is not set.", file=sys.stderr)
        print("  export ENCRYPT_SECRET='your-long-random-master-secret'", file=sys.stderr)
        sys.exit(1)

    if not SOURCE_DIR.exists():
        print(f"ERROR: Source directory '{SOURCE_DIR}' does not exist.", file=sys.stderr)
        sys.exit(1)

    html_files = sorted(SOURCE_DIR.rglob("*.html"))
    rel_paths = {f: str(f.relative_to(SOURCE_DIR)) for f in html_files}

    if args.file:
        html_files = [f for f in html_files if rel_paths[f] == args.file or f.name == args.file]
        if not html_files:
            print(f"ERROR: '{args.file}' not found in {SOURCE_DIR}", file=sys.stderr)
            sys.exit(1)

    if args.skip_unchanged:
        def _is_up_to_date(src: Path, rel: str) -> bool:
            out = OUTPUT_DIR / rel
            return out.exists() and out.stat().st_mtime >= src.stat().st_mtime

        skipped = [f for f in html_files if _is_up_to_date(f, rel_paths[f])]
        html_files = [f for f in html_files if not _is_up_to_date(f, rel_paths[f])]
        if skipped:
            print(f"Skipping {len(skipped)} up-to-date file(s): {', '.join(rel_paths[f] for f in skipped)}")

    if not html_files:
        print(f"No HTML files to process in {SOURCE_DIR}")
        sys.exit(0)

    passwords = {rel_paths[f]: derive_password(master_secret, rel_paths[f]) for f in html_files}

    if args.show:
        print(f"\nDerived passwords for files in {SOURCE_DIR.relative_to(WORKSPACE)}/")
        print("(Master secret not shown — store it in your password manager)")
        print_password_table(passwords)
        return

    template_note = f" (template: {TEMPLATE.name})" if TEMPLATE.exists() else " (default template)"
    print(f"\nEncrypting {len(html_files)} file(s){template_note}")
    print(f"  {SOURCE_DIR.relative_to(WORKSPACE)}/ → {OUTPUT_DIR.relative_to(WORKSPACE)}/\n")

    results = {}
    for src in html_files:
        rel = rel_paths[src]
        out_dir = OUTPUT_DIR / Path(rel).parent
        print(f"  {rel} ...", end=" ", flush=True)
        ok = encrypt_file(src, out_dir, passwords[rel])
        results[rel] = "OK" if ok else "FAILED"
        print(results[rel])

    print("\nPasswords (share individually per recipient):")
    print_password_table(passwords, results)

    failed = [rel for rel, status in results.items() if status != "OK"]
    if failed:
        print(f"WARNING: {len(failed)} file(s) failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
