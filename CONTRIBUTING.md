# Contributing to Sentinela

Thanks for your interest in contributing. Sentinela is a small project maintained on a best-effort basis — your patience is appreciated.

## Ground rules

- **Open an issue before a large PR.** For typo fixes, small bug fixes, or clearly-scoped improvements, just send the PR. For anything that touches the analyzer flow, the data model, or adds a dependency, open an issue first so we can align on direction.
- **Keep the scope tight.** One concern per PR. Refactor PRs and feature PRs should not be mixed.
- **No new dependencies without a reason.** The dependency list in [`requirements.txt`](requirements.txt) is intentionally short.
- **Match the existing style.** This codebase is pragmatic, not dogmatic. Read a couple of files before sending changes.

## Reporting bugs

Open an issue with:

1. What you did (steps to reproduce)
2. What you expected
3. What happened instead
4. Python version, OS, and whether you're on SQLite or PostgreSQL

If the bug involves AWS API responses, **redact account IDs, ARNs, and resource names** before pasting logs.

## Suggesting features

Open an issue tagged `enhancement` with:

- The problem the feature solves (not the solution)
- Who experiences this problem and how often
- A rough sketch of the solution, if you have one

Features that align with the [Future ideas](README.md#future-ideas) section are more likely to land.

## Development setup

See the [Quickstart](README.md#quickstart) in the README and [SETUP.md](SETUP.md) for the full operational walkthrough.

```bash
git clone https://github.com/jacksonmlk/sentinela-opensource.git
cd sentinela-opensource
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill in ANTHROPIC_API_KEY and ADMIN_SECRET_TOKEN
uvicorn app.main:app --reload --port 8000
```

## Pull requests

Before opening a PR:

- [ ] The app starts cleanly (`uvicorn app.main:app --reload`)
- [ ] You can log into `/admin` with the token from your `.env`
- [ ] If you touched the analyzer, you ran at least one end-to-end analysis against a sandbox AWS account
- [ ] Commit messages are descriptive (we follow Conventional Commits loosely: `feat:`, `fix:`, `docs:`, `refactor:`, `perf:`, `chore:`)

PR description should answer:

- **What** changed
- **Why** it changed (link to issue if applicable)
- **How** to verify it works

## Code of conduct

Be kind. Disagree with ideas, not with people. That's it.

## Security issues

**Do not open a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md).
