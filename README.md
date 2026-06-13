# ecology-dashboards

Encrypted Ecology daily dashboards served via GitHub Pages.

- `public-encrypted/` — plaintext source (private repo only, never served)
- `public/` — StatiCrypt-encrypted output, served by GitHub Pages
- One master secret in `.env` (gitignored); per-file passwords derived via HMAC-SHA256.

Drop HTML in `public-encrypted/`, commit (pre-commit hook encrypts), push.
`make encrypt-show` prints the per-file passwords.
