"""Per-page password versioning: revoke ONE page without changing everyone else's.

WHY THIS EXISTS (30/08/2026). Every page already gets a unique password, because it is
HMAC-SHA256(master_secret, relative_path). But all of them hang off one master secret, so
the only way to revoke a single page was to change that secret, which changes EVERY page's
password and means the whole warehouse relearns theirs.

That became a real question when a board was proposed for someone outside the business
(the batch page for Dianne's husband, see reports/daily/warehouse/BATCH-PICKUP-PAGE.md).
Staff move on, and revoking a former staff member's partner should not cost everyone a new
password.

So a page may now carry a VERSION, and the version goes into the hashed message. Bump one
page's version, republish that page, and only that page's password moves.

THE LOAD-BEARING PROPERTY IS BACKWARDS COMPATIBILITY: an unversioned page, and a page
explicitly at v1, must both hash exactly as they did before this file existed. If that ever
breaks, every board in the warehouse locks out at once with no warning, and the failure
arrives as "the TV is asking for a password nobody has". Tests 1-3 are that property.

Run: python3 scripts/encrypt/test_password_versions.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import encrypt_public as ep

SECRET = "test-secret-not-the-real-one"
FAILURES = []


def check(label, cond):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        FAILURES.append(label)


def _with_versions(payload):
    """A throwaway workspace holding a password-versions.json, or none if payload is None."""
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    if payload is not None:
        (root / "password-versions.json").write_text(payload)
    return tmp, root


def test_absent_file_changes_nothing():
    """The whole warehouse depends on this one."""
    tmp, root = _with_versions(None)
    with tmp, patch.object(ep, "WORKSPACE", root):
        v = ep.load_versions()
        for page in ("warehouse.html", "founder.html", "dashboard.html", "reports/q1.html"):
            check(f"no versions file: {page} hashes as before",
                  ep.password_message(page, v) == page)


def test_v1_is_the_original():
    """v1 means 'never revoked', so it must be identical to unversioned - otherwise
    writing the file down for the first time would lock everyone out."""
    tmp, root = _with_versions(json.dumps({"warehouse.html": 1, "founder.html": 1}))
    with tmp, patch.object(ep, "WORKSPACE", root):
        v = ep.load_versions()
        check("v1 == unversioned for warehouse.html",
              ep.password_message("warehouse.html", v) == "warehouse.html")
        check("v1 == unversioned for founder.html",
              ep.password_message("founder.html", v) == "founder.html")


def test_bump_changes_only_that_page():
    tmp, root = _with_versions(json.dumps({"batch.html": 2}))
    with tmp, patch.object(ep, "WORKSPACE", root):
        v = ep.load_versions()
        bumped = ep.derive_password(SECRET, ep.password_message("batch.html", v))
        original = ep.derive_password(SECRET, "batch.html")
        check("a bumped page gets a different password", bumped != original)
        check("the bump is deterministic",
              bumped == ep.derive_password(SECRET, ep.password_message("batch.html", v)))
        for other in ("warehouse.html", "founder.html", "dashboard.html"):
            check(f"bumping batch.html leaves {other} untouched",
                  ep.derive_password(SECRET, ep.password_message(other, v))
                  == ep.derive_password(SECRET, other))


def test_each_bump_is_distinct():
    """Revoking twice must not hand back the password from the first revocation."""
    seen = set()
    for n in (1, 2, 3, 4):
        tmp, root = _with_versions(json.dumps({"batch.html": n}))
        with tmp, patch.object(ep, "WORKSPACE", root):
            v = ep.load_versions()
            seen.add(ep.derive_password(SECRET, ep.password_message("batch.html", v)))
    check("four versions produce four distinct passwords", len(seen) == 4)


def test_malformed_file_refuses_rather_than_reverting():
    """Failing OPEN here would silently un-revoke: a corrupt or truncated versions file
    would send every page back to its v1 password, handing access back to whoever was
    revoked, and the publish would look completely normal. So it must refuse."""
    for bad in ("{not json", '{"batch.html": "two"}', '{"batch.html": 0}', '{"batch.html": -1}'):
        tmp, root = _with_versions(bad)
        with tmp, patch.object(ep, "WORKSPACE", root):
            try:
                ep.load_versions()
                check(f"malformed versions file refused: {bad[:24]!r}", False)
            except SystemExit:
                check(f"malformed versions file refused: {bad[:24]!r}", True)


def test_versions_are_reported_without_values():
    """A silent revocation is as bad as a silent un-revocation - the publish has to say
    which pages are not on v1, and must still never print a password."""
    tmp, root = _with_versions(json.dumps({"batch.html": 3}))
    with tmp, patch.object(ep, "WORKSPACE", root):
        v = ep.load_versions()
        line = ep.describe_versions(v)
        check("the report names the versioned page", "batch.html" in line)
        check("the report gives its version", "3" in line)
        pw = ep.derive_password(SECRET, ep.password_message("batch.html", v))
        check("the report contains no password value", pw not in line)


if __name__ == "__main__":
    for t in (test_absent_file_changes_nothing, test_v1_is_the_original,
              test_bump_changes_only_that_page, test_each_bump_is_distinct,
              test_malformed_file_refuses_rather_than_reverting,
              test_versions_are_reported_without_values):
        t()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} FAILED")
        sys.exit(1)
    print("all passed")
