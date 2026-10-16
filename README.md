# ecology-dashboards

Encrypted Ecology daily dashboards served via GitHub Pages.

- `public-encrypted/` — plaintext source (private repo only, never served)
- `public/` — StatiCrypt-encrypted output, served by GitHub Pages
- One master secret in `.env` (gitignored); per-file passwords derived via HMAC-SHA256.

Drop HTML in `public-encrypted/`, commit (pre-commit hook encrypts), push.

## Reading a password

`make encrypt-show` reports which pages exist and whether their passwords are distinct.
It never prints a value, so it is safe to run anywhere.

`make encrypt-reveal` prints the actual passwords (add `FILE=warehouse.html` for one page).
**Run it only in a real terminal window — never inside Claude Code, and never via `!`.**
Anything printed into a captured tool call is written to that session's transcript
permanently. The script refuses when stdout is not a tty, but the rule is the point;
the check is only the backstop.

Nothing else prints a password. The encrypt run itself used to, which mattered because
lefthook encrypts on every commit and every board publish commits from a captured call —
24 live passwords across 8 transcript files had to be scrubbed on 01/08/2026.
