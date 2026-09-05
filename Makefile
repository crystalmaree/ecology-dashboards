encrypt:
	python3 scripts/encrypt/encrypt_public.py

# SAFE. Reports which pages exist, that each has a password, and whether the passwords
# are distinct. Never prints a value, so it is safe to run anywhere, Claude Code included.
encrypt-show:
	python3 scripts/encrypt/encrypt_public.py --check

# PRINTS ACTUAL PASSWORDS. Run this ONLY in a real terminal window.
# NEVER run it inside Claude Code, and never via `!` - the output is captured into the
# session transcript and stays there. The script refuses when stdout is not a tty, which
# is the mechanical half of this warning; treat the warning as the reason, not the check.
# One page only:  make encrypt-reveal FILE=warehouse.html
encrypt-reveal:
	python3 scripts/encrypt/encrypt_public.py --show $(if $(FILE),--file $(FILE))
