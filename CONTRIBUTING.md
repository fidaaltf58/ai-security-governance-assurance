# Contributing

Thanks for your interest. This is a portfolio/reference project, but issues and
pull requests are welcome.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest          # run the test suite
ruff check .    # lint
uvicorn app.main:app --reload
```

## Expectations for a change

- **Tests pass** (`pytest`) and **lint is clean** (`ruff check .`).
- New behaviour comes with a test.
- Risk-scoring and framework-mapping logic stays pure and covered.
- No secrets, real engagement data, or `.env` files in commits.

## Commit messages

Use conventional-commit style, e.g.:

```
feat: add CSV export for the risk register
fix: clamp residual score when no controls are mapped
test: cover unknown OWASP id rejection
docs: expand threat model
ci: pin actions to commit SHAs
```

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) — do not open a public issue with a
working exploit.
