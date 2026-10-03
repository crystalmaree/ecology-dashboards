import contextlib, io, sys, os, tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import encrypt_public as ep

TEST_SECRET = "test-secret-not-the-real-one"


def _run_main(argv, names, secret=TEST_SECRET, isatty=False, env=None):
    """Run main() against a throwaway workspace, with staticrypt mocked out.

    Returns everything the run wrote to stdout+stderr, so a test can assert on
    what a human (or a transcript) would actually have seen.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "public-encrypted"
        src.mkdir()
        for n in names:
            (src / n).write_text("<html></html>")

        out_buf, err_buf = io.StringIO(), io.StringIO()
        out_buf.isatty = lambda: isatty

        environ = {"ENCRYPT_SECRET": secret}
        environ.update(env or {})

        with patch.object(ep, "WORKSPACE", root), \
             patch.object(ep, "SOURCE_DIR", src), \
             patch.object(ep, "OUTPUT_DIR", root / "public"), \
             patch.object(ep, "TEMPLATE", root / "no-template.html"), \
             patch.dict(os.environ, environ, clear=True), \
             patch("encrypt_public.subprocess.run") as mock_run, \
             patch.object(sys, "argv", ["encrypt_public.py"] + argv):
            mock_run.return_value = MagicMock(returncode=0)
            with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                try:
                    ep.main()
                except SystemExit:
                    pass
        return out_buf.getvalue() + err_buf.getvalue()


def test_normal_encrypt_run_never_prints_a_password():
    """The pre-commit hook (lefthook.yml) runs this on every commit to the Pages repo,
    and every board publish commits from a captured Bash call. So a password printed by
    an ordinary run lands in a transcript on every publish - which is how 23 copies of
    a live password accumulated across 8 transcript files before 01/08/2026.
    """
    output = _run_main([], ["warehouse.html", "founder.html"])
    for name in ("warehouse.html", "founder.html"):
        pwd = ep.derive_password(TEST_SECRET, name)
        assert pwd not in output, f"an ordinary encrypt run printed {name}'s password"


def test_check_mode_names_the_pages_without_revealing_a_password():
    output = _run_main(["--check"], ["warehouse.html", "founder.html"])
    assert "warehouse.html" in output and "founder.html" in output, \
        "--check must report which pages exist"
    for name in ("warehouse.html", "founder.html"):
        assert ep.derive_password(TEST_SECRET, name) not in output, \
            "--check must never print a value"


def test_check_mode_reports_that_passwords_are_distinct():
    output = _run_main(["--check"], ["warehouse.html", "founder.html"])
    assert "distinct" in output.lower(), \
        "--check must give a distinct/shared verdict, since that is the property that matters"


def test_check_mode_reports_a_collision_when_two_pages_share_a_password():
    """The verdict has to be computed, not assumed. If derivation ever degrades to a
    constant, --check is the only thing standing between that and a silent shared password.
    """
    with patch.object(ep, "derive_password", lambda secret, rel: "identical-for-every-page"):
        output = _run_main(["--check"], ["warehouse.html", "founder.html"])
    assert "shared" in output.lower() or "not distinct" in output.lower(), \
        "--check must report a collision rather than claiming pages are distinct"


def test_show_refuses_when_stdout_is_not_a_terminal():
    """`!` inside Claude Code, a pipe, and a captured Bash tool call all present as
    a non-tty. That is exactly the case where a printed password becomes permanent.
    """
    output = _run_main(["--show"], ["warehouse.html"], isatty=False)
    assert ep.derive_password(TEST_SECRET, "warehouse.html") not in output, \
        "--show printed a password into a non-interactive stream"
    assert "terminal" in output.lower(), "--show should explain why it refused"


def test_show_prints_the_password_at_a_real_terminal():
    output = _run_main(["--show"], ["warehouse.html"], isatty=True)
    assert ep.derive_password(TEST_SECRET, "warehouse.html") in output, \
        "--show must still work for Crystal at a real terminal"


def test_remember_flags_added_for_warehouse_html():
    with patch("encrypt_public.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        ep.encrypt_file(Path("public-encrypted/warehouse.html"), Path("public"), "pw123",
                         remember_days=ep.REMEMBER_DAYS.get("warehouse.html"))
        cmd = mock_run.call_args[0][0]
        assert "--remember" in cmd, "warehouse.html must get --remember"
        assert cmd[cmd.index("--remember")+1] == "30", "expected 30-day remember window"
        assert "--share-remember" in cmd


def test_remember_flags_added_for_founder_html():
    """The founder board is a phone board too. Without --remember its unlock lives in
    sessionStorage, which Safari discards when the tab is backgrounded - the same defect
    warehouse.html was given 30 days to fix."""
    with patch("encrypt_public.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        ep.encrypt_file(Path("public-encrypted/founder.html"), Path("public"), "pw789",
                         remember_days=ep.REMEMBER_DAYS.get("founder.html"))
        cmd = mock_run.call_args[0][0]
        assert "--remember" in cmd, "founder.html must get --remember"
        assert cmd[cmd.index("--remember")+1] == "30"


def test_remembered_pages_do_not_share_one_storage_key():
    """Two remembered boards on one origin must not evict each other.

    The keys were fixed strings, so unlocking one board overwrote the other's stored
    passphrase and every switch meant re-entering a password. Harmless while only one
    page was remembered; a second is what makes it bite.
    """
    tmpl = (Path(__file__).parent / "template.html").read_text()
    assert 'rememberPassphraseKey: "staticrypt_passphrase"' not in tmpl, \
        "the passphrase key must not be a fixed string shared by every page"
    assert "staticryptPage" in tmpl, "expected the key to be namespaced per page"
    assert len(ep.REMEMBER_DAYS) >= 2, \
        "this test is only meaningful once more than one page is remembered"


def test_no_remember_flags_for_other_files():
    with patch("encrypt_public.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        ep.encrypt_file(Path("public-encrypted/dashboard.html"), Path("public"), "pw456",
                         remember_days=ep.REMEMBER_DAYS.get("dashboard.html"))
        cmd = mock_run.call_args[0][0]
        assert "--remember" not in cmd
        assert "--share-remember" not in cmd


if __name__ == "__main__":
    fails = 0
    for _name, _fn in sorted(list(globals().items())):
        if _name.startswith("test_") and callable(_fn):
            try:
                _fn(); print("PASS", _name)
            except AssertionError as _e:
                fails += 1; print("FAIL", _name, "-", _e)
            except Exception as _e:
                fails += 1; print("ERROR", _name, "-", repr(_e))
    print(("\n%d FAILED" % fails) if fails else "\nALL PASS")
    sys.exit(1 if fails else 0)
