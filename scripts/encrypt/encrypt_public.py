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

Revoking ONE page: password-versions.json
  Sharing a page is easy; UN-sharing it used to mean changing the master secret, which
  changes every password in the warehouse. So a page may carry a version, and the version
  goes into the hashed message: bump it, republish that file, and only that page moves.

      {"batch.html": 2}        # page -> version, integer >= 1

  v1 and "absent" both hash the bare path, so creating this file changes nothing. A file
  that exists but does not parse is a HARD ERROR rather than a fallback: failing open
  would quietly restore access for a page you had revoked, and the publish would look
  entirely normal. `--check` names any page not on v1, so a revocation is visible.

Usage:
    python3 scripts/encrypt/encrypt_public.py                    # encrypt all files → public/
    python3 scripts/encrypt/encrypt_public.py --check            # which pages exist + are their passwords distinct (NO values)
    python3 scripts/encrypt/encrypt_public.py --show             # print ACTUAL passwords — real terminal only, see below
    python3 scripts/encrypt/encrypt_public.py --skip-unchanged    # skip files whose encrypted output is newer than source
    python3 scripts/encrypt/encrypt_public.py --file reports/q1.html # one file only

Printing passwords (read this before using --show):
    No mode other than --show prints a password value, and --show refuses unless stdout
    is a real terminal. This is not politeness — the pre-commit hook in lefthook.yml runs
    this script on every commit to this repo, and every board publish commits from a
    captured tool call. While an ordinary run printed the password table, every publish
    wrote every live password into a session transcript; 24 copies across 8 transcript
    files had to be scrubbed on 01/08/2026. A pipe, a captured Bash call, and `!` inside
    Claude Code all present as a non-tty, which is why the tty check is the gate.
    Use `make encrypt-show` (safe) to confirm setup; `make encrypt-reveal` only when you
    genuinely need a value, and only in a real terminal window.

Requirements:
    npx (Node.js) — StatiCrypt is run via npx, no global install needed.
"""

import argparse
import base64
import hashlib
import hmac
import json
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

# Files where the "Remember me" checkbox (StatiCrypt's built-in localStorage persistence,
# not a hand-rolled mechanism) is worth enabling. warehouse.html is checked from Crystal's
# phone, where iOS/Android backgrounding a tab would otherwise force frequent re-entry.
# Every other encrypted page keeps StatiCrypt's default (no persistence beyond the page load).
# Pages whose unlock PERSISTS, and for how long. A page absent from here gets no
# --remember at all, so its unlock lives in sessionStorage and Safari discards it when
# the tab is backgrounded - which is exactly why warehouse.html was given 30 days.
# founder.html is a phone board too, so it needs the same treatment; the per-page key
# namespacing in template.html is what stops the two from evicting each other.
# dianne.html is the same shape of problem again and then some: it is checked from a phone, a
# few times across an afternoon, with app-switching in between - so without --remember its
# unlock sits in sessionStorage and Safari discards it on every backgrounding. The person
# using it would re-type a 24-character password nearly every glance, which is how a
# nice-to-have gets abandoned inside a week. Persisting the unlock is safe to grant here
# because his page can now be revoked ON ITS OWN by bumping password-versions.json, without
# touching anyone else's password.
REMEMBER_DAYS = {"warehouse.html": 30, "founder.html": 30, "dianne.html": 30}


def derive_password(master_secret: str, relative_path: str) -> str:
    key = master_secret.encode("utf-8")
    msg = relative_path.encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)[:24].decode("ascii")


# --- per-page password versions -------------------------------------------------
# Every page already has its own password, but all of them hang off ONE master secret,
# so revoking a single page meant changing that secret and therefore every password in
# the warehouse. A version lets one page be revoked alone: bump it, republish that file.
#
# Added 30/08/2026 for the batch page for Dianne's husband - the first board handed to
# someone outside the business, where "she has left, revoke his access" is a normal
# event that should not cost everyone a new password.
VERSIONS_FILENAME = "password-versions.json"


def versions_path() -> Path:
    """Resolved through WORKSPACE at CALL time, never bound at import. The tests patch
    WORKSPACE, and a module-level constant would keep pointing at the real repo - the
    same trap the board's raw cache path hit by binding common.CONFIG at import."""
    return WORKSPACE / VERSIONS_FILENAME


def load_versions() -> dict:
    """Absent file means every page is unversioned, which is the world before this
    existed and must stay valid.

    A file that EXISTS but does not parse is a hard error, deliberately. Failing open
    would send every page back to its v1 password, silently handing access back to
    whoever was revoked, and the publish would look entirely normal. A publish that
    refuses is recoverable; one that quietly un-revokes is not.
    """
    p = versions_path()
    if not p.exists():
        return {}
    try:
        raw = json.loads(p.read_text())
    except Exception as exc:
        sys.exit(f"ERROR: {VERSIONS_FILENAME} is present but unreadable ({exc}).\n"
                 "  Refusing to publish: falling back to unversioned passwords would\n"
                 "  silently restore access for any page that has been revoked.")
    if not isinstance(raw, dict):
        sys.exit(f"ERROR: {VERSIONS_FILENAME} must be an object of page -> version.")
    for page, ver in raw.items():
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            sys.exit(f"ERROR: {VERSIONS_FILENAME}: version for {page!r} must be an "
                     f"integer >= 1, got {ver!r}.")
    return raw


def password_message(relative_path: str, versions: dict) -> str:
    """What actually gets hashed. v1 (and absent) hash the bare path, so writing this
    file down for the first time cannot change a single existing password."""
    ver = versions.get(relative_path, 1)
    return relative_path if ver <= 1 else f"{relative_path}:v{ver}"


def describe_versions(versions: dict) -> str:
    """One line naming any page not on v1. A revocation that nobody can see in the
    publish output is as dangerous as one that silently reverts."""
    bumped = {p: v for p, v in versions.items() if v > 1}
    if not bumped:
        return "  All pages on password v1 (no page has been revoked)."
    parts = ", ".join(f"{p} @ v{v}" for p, v in sorted(bumped.items()))
    return f"  Revoked/rotated pages: {parts}"


def encrypt_file(src: Path, output_dir: Path, password: str, remember_days: int = None) -> bool:
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
    if remember_days:
        cmd += ["--remember", str(remember_days), "--share-remember"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    staticrypt error: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def print_password_table(passwords: dict, results: dict = None):
    """Prints ACTUAL password values. Only ever reached via --show, behind the tty gate."""
    print()
    print(f"  {'File':<45} Password")
    print(f"  {'-'*45} {'-'*24}")
    for name, pwd in passwords.items():
        status = f"  [{results[name]}]" if results else ""
        print(f"  {name:<45} {pwd}{status}")
    print()


def print_safe_summary(passwords: dict, results: dict = None):
    """Report what a person actually needs to know - which pages exist, that each has a
    password, and whether the passwords are distinct - without emitting a single value.

    Length is shown rather than the value because it is enough to spot a truncated or
    empty derivation while being useless to anyone reading the transcript later.
    """
    print()
    print(f"  {'File':<45} {'Password':<12} Status")
    print(f"  {'-'*45} {'-'*12} ------")
    for name, pwd in passwords.items():
        status = results.get(name, "") if results else ""
        print(f"  {name:<45} {f'{len(pwd)} chars':<12} {status}")
    print()

    if len(passwords) > 1:
        if len(set(passwords.values())) == len(passwords):
            print("  Every page has a DISTINCT password.")
        else:
            print("  WARNING: passwords are SHARED - two or more pages derive the same value.")
            print("  That defeats per-page sharing. Check derive_password() before publishing.")
    print("  Values are not shown here, by design.")
    print("  Need one? `make encrypt-reveal` in a real terminal window - never inside Claude Code.")
    print()


def show_is_permitted() -> bool:
    """A pipe, a captured tool call, and `!` inside Claude Code all present as a non-tty.
    Those are precisely the contexts where a printed password becomes a permanent record,
    so the tty is the signal we gate on rather than trusting a comment to be obeyed.
    """
    if os.environ.get("ENCRYPT_SHOW_FORCE") == "1":
        return True
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--show", action="store_true",
                        help="print ACTUAL password values (real terminal only)")
    parser.add_argument("--check", action="store_true",
                        help="report which pages exist and whether passwords are distinct, without values")
    parser.add_argument("--skip-unchanged", action="store_true")
    parser.add_argument("--file", metavar="FILENAME")
    args = parser.parse_args()

    master_secret = os.environ.get("ENCRYPT_SECRET", "")
    if not master_secret:
        print("ERROR: ENCRYPT_SECRET environment variable is not set.", file=sys.stderr)
        print("  Set it in .env, or export it in your shell. See README.md.", file=sys.stderr)
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

    versions = load_versions()
    passwords = {rel_paths[f]: derive_password(
        master_secret, password_message(rel_paths[f], versions)) for f in html_files}

    if args.check:
        print(f"\nEncrypted pages in {SOURCE_DIR.relative_to(WORKSPACE)}/")
        print_safe_summary(passwords)
        print(describe_versions(versions))
        print()
        return

    if args.show:
        if not show_is_permitted():
            print("REFUSING to print passwords: stdout is not a terminal.", file=sys.stderr)
            print("  A pipe, a captured tool call, and `!` inside Claude Code all look like", file=sys.stderr)
            print("  this, and anything printed there is written to a transcript for good.", file=sys.stderr)
            print("  Run `make encrypt-reveal` in a real terminal window instead, or", file=sys.stderr)
            print("  `make encrypt-show` for a report that never prints a value.", file=sys.stderr)
            sys.exit(2)
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
        ok = encrypt_file(src, out_dir, passwords[rel], remember_days=REMEMBER_DAYS.get(rel))
        results[rel] = "OK" if ok else "FAILED"
        print(results[rel])

    # NEVER print values here. This path runs from lefthook's pre-commit hook on every
    # commit to this repo, and every board publish commits from a captured tool call.
    print("\nPer-page passwords (share individually per recipient):")
    print_safe_summary(passwords, results)

    failed = [rel for rel, status in results.items() if status != "OK"]
    if failed:
        print(f"WARNING: {len(failed)} file(s) failed: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
