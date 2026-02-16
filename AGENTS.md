# AGENTS.md — Root

## Project Purpose
This repository is a project scaffold providing CI/CD, git hooks, and versioning infrastructure for autonomous coding agents and human developers. All new code should follow the conventions documented here and in per-module `AGENTS.md` files. When application code is added, update this root file and create per-module documentation.

## Architecture Overview
```
repo/
├── .githooks/          # Git hooks (pre-commit, pre-push)
├── .github/workflows/  # CI/CD pipeline (GitHub Actions)
├── .gitconfig           # Local git config (hooksPath)
├── .releaserc.json      # semantic-release configuration
├── version.json         # Project version metadata
├── VERSION              # Semver version file
└── AGENTS.md            # This file — project conventions
```

- **No application code exists yet.** When code is added, create per-module `AGENTS.md` files and update this root file.
- Data flow and services will be documented as they are introduced.

## Tech Stack
| Layer       | Technology                         |
|-------------|------------------------------------|
| VCS         | Git                                |
| CI/CD       | GitHub Actions                     |
| Versioning  | semantic-release, Conventional Commits |
| Hooks       | Bash scripts in `.githooks/`       |
| Config      | JSON (`version.json`, `.releaserc.json`) |

When application code is added, update this table with languages, frameworks, databases, and runtimes.

## CRITICAL RULES

1. **Conventional Commits required.** Every commit message MUST follow the format `type(scope): description` (e.g., `feat(api): add user endpoint`, `fix(core): null check`). Valid types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `ci`, `build`, `revert`. This drives automated versioning via semantic-release.

2. **No unresolved work markers in committed code.** The pre-commit hook rejects any staged files containing unresolved work markers (the words that start with "TO" + "DO" or "FIX" + "ME"). If you need to track work, create a GitHub Issue instead.

3. **All hooks must pass before push.** The pre-push hook runs format checks, linting, and tests. Never use `--no-verify` in production branches. The only exception is the initial indexation commit (`chore: cluster indexation`).

4. **`version.json` and `VERSION` are source-of-truth for versioning.** Do NOT manually edit these files — they are updated by semantic-release during CI. Manual edits will cause version conflicts.

5. **CI must pass on all pull requests.** The `check` job in `.github/workflows/ci.yml` gates all merges. Do not merge PRs with failing CI. Add tests for every new feature or bug fix.

6. **Per-module AGENTS.md files are mandatory.** When creating a new crate, package, service, or module directory, always create an `AGENTS.md` inside it documenting: purpose, public API, key files, testing instructions, and gotchas.

7. **Keep `.githooks/` scripts POSIX-compatible where possible.** Use `#!/bin/bash` with `set -e`. Always support `SKIP_GIT_HOOKS=1` for emergency bypasses. Document any new hooks in this file.

8. **Security: never commit secrets.** No API keys, tokens, passwords, or credentials in source code. Use environment variables and reference them via `${{ secrets.* }}` in CI workflows.

9. **File size limit: 5 MB.** The pre-commit hook rejects files larger than 5 MB. Use Git LFS for large binary assets.

10. **JSON validation is enforced.** All `.json` files are validated on commit. Malformed JSON will be rejected by the pre-commit hook.

## What TO DO
- Read the `AGENTS.md` in any directory before editing files there.
- Write tests for all new functionality.
- Use Conventional Commits for all commit messages.
- Create per-module `AGENTS.md` files when adding new directories.
- Run git hooks locally before pushing (they run automatically if `.gitconfig` is applied).
- Keep CI green — fix failures immediately.
- Update this file when adding new tech stack components, services, or conventions.

## What NOT TO DO
- Do NOT commit unresolved work marker comments — the pre-commit hook will reject them.
- Do NOT manually edit `VERSION` or `version.json` — semantic-release manages these.
- Do NOT skip git hooks with `--no-verify` on `main` branch.
- Do NOT merge PRs with failing CI checks.
- Do NOT commit secrets, credentials, or `.env` files.
- Do NOT create modules/packages without a corresponding `AGENTS.md`.

## Build & Test Commands

Since no application code exists yet, the following are infrastructure commands:

```bash
# Apply git hooks configuration
git config core.hooksPath .githooks

# Run pre-commit checks manually
./.githooks/pre-commit

# Run full pre-push quality gate manually
./.githooks/pre-push

# Check current version
cat VERSION
cat version.json
```

When application code is added, document language-specific commands here:
```bash
# Example (update when tech stack is chosen):
# npm test          — for Node.js projects
# cargo test        — for Rust projects
# pytest            — for Python projects
# go test ./...     — for Go projects
```

## Git Hooks Documentation

### `.githooks/pre-commit`
- **Trigger:** Runs before every `git commit`.
- **Checks:**
  - Scans staged files for unresolved work markers. Rejects the commit if any are found.
  - Validates all staged `.json` files for correct syntax.
  - Rejects files larger than 5 MB.
  - Warns about potential secrets (API keys, tokens, passwords).
- **Bypass:** Set `SKIP_GIT_HOOKS=1` environment variable.

### `.githooks/pre-push`
- **Trigger:** Runs before every `git push`.
- **Checks:**
  - Validates that `AGENTS.md` exists at the project root.
  - Validates that `VERSION` file exists and is non-empty.
  - Validates that `version.json` is valid JSON.
  - Validates that `.releaserc.json` is valid JSON.
  - Scans the entire project for unresolved work markers.
  - Runs language-specific format, lint, test, and build checks when tooling is detected (Node.js, Rust, Python, Go).
- **Bypass:** Set `SKIP_GIT_HOOKS=1` environment variable.

## Workflow
- Read `AGENTS.md` in any subdirectory before editing there.
- Update this file if repository conventions change.
