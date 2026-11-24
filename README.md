# safe-vibe — AI & Vibe-Coding Security Guard for Git Diffs

AI coding assistants ship fast — and quietly slip in hardcoded API keys, empty `catch {}` blocks, raw SQL interpolation, and `eval()` calls.
**`safe-vibe`** audits **only your newly added Git diff lines** (`+`) and blocks risky code before it ever reaches `git commit`, with zero external dependencies.

![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)
![Zero Dependencies](https://img.shields.io/badge/dependencies-0-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

## Installation & Quickstart

Run directly in any Git repository with staged changes, install the pre-commit hook, or install globally:

```sh
# Audit staged changes without installing
npx safe-vibe

# Install the non-destructive Git pre-commit hook
npx safe-vibe install

# Or install globally
npm install -g safe-vibe
safe-vibe
```

## Why `safe-vibe`?

| Capability | `safe-vibe` | Traditional Linters (ESLint / Ruff) | Secret Scanners (Gitleaks / TruffleHog) | Heavy SAST Suites (Semgrep / SonarQube) |
| :--- | :---: | :---: | :---: | :---: |
| Zero dependencies (`npx`-ready) | ✅ | ❌ | ❌ (Go binary) | ❌ (Python / JVM) |
| Audits only newly added diff lines (zero legacy noise) | ✅ | ❌ | Partial | Partial |
| Catches secrets + silent catches + injections + AI stubs together | ✅ | Partial | ❌ (Secrets only) | ✅ (Requires config) |
| One-command non-destructive `.git/hooks/pre-commit` install | ✅ | Manual / Husky | Manual | Manual / CI |

## Terminal Output

When issues are detected in staged changes (`git diff --cached -U0`):

```text
safe-vibe: Found 3 issue(s) across 18 added staged line(s):

[CRITICAL] src/config.js:14 (secret-openai-key)
  Potential hardcoded OpenAI API key detected
  > const apiKey = "sk-00000000000000000000example";
  Tip: Load OpenAI API keys from process.env or a secrets manager rather than source code.

[HIGH] src/worker.js:42 (silent-empty-catch)
  Empty catch block silently swallows errors
  > } catch (err) {}
  Tip: Log, rethrow, or explicitly handle the caught error instead of leaving catch empty.

[CRITICAL] src/db.js:27 (dangerous-raw-sql)
  Raw SQL string interpolation or concatenation risks SQL injection
  > const rows = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
  Tip: Use parameterized queries or prepared statements ($1, ?) instead of interpolating variables into SQL.

✖ Commit blocked by safe-vibe (2 critical, 1 high)
```

When your staged diff is clean:

```text
✔ Safe to commit — no vibe-coding traps found (audited 12 added staged line(s))
```

### CLI Options & Commands

```sh
# Audit staged changes (default — blocks on critical & high issues)
safe-vibe

# Audit unstaged working tree changes
safe-vibe --unstaged

# Strict mode — also block commits on medium issues (TODO: implement / FIXME)
safe-vibe --strict

# Machine-readable JSON output
safe-vibe --json

# Install or uninstall the Git pre-commit hook
safe-vibe install
safe-vibe uninstall

# Version & help
safe-vibe --version
safe-vibe --help
```

## Pre-Commit Hook Setup

Install the pre-commit hook in your repository:

```sh
safe-vibe install
```

- Creates `.git/hooks/pre-commit` (`chmod 0755`) if one does not exist, running `safe-vibe` (or `npx --no-install safe-vibe`).
- If you already have a `.git/hooks/pre-commit` script, `safe-vibe install` **appends** a `# --- safe-vibe start ---` / `# --- safe-vibe end ---` block without overwriting your existing hooks.
- Run `safe-vibe uninstall` at any time to cleanly remove the marked block (or delete the hook file if nothing else remains).

## Rule Reference

| Rule ID | Category | Severity | What It Catches |
| --- | --- | --- | --- |
| `secret-aws-access-key` | Secrets | `critical` | Hardcoded AWS access key IDs (`AKIA...`, `ASIA...`) |
| `secret-github-token` | Secrets | `critical` | Hardcoded GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) |
| `secret-anthropic-key` | Secrets | `critical` | Hardcoded Anthropic API keys (`sk-ant-...`) |
| `secret-openai-key` | Secrets | `critical` | Hardcoded OpenAI API keys (`sk-...`, `sk-proj-...`) |
| `secret-private-key` | Secrets | `critical` | Private key PEM headers (`-----BEGIN ... PRIVATE KEY-----`) |
| `secret-generic-assignment` | Secrets | `critical` | High-entropy credential literals assigned to `api_key`, `secret`, `password`, `auth_token`, etc. |
| `silent-empty-catch` | Error Handling | `high` | Single-line or multi-line empty `catch (...) {}` blocks |
| `silent-empty-except` | Error Handling | `high` | Single-line or multi-line Python `except ...: pass` / `...` blocks |
| `dangerous-eval` | Injection | `critical` | `eval()`, `window.eval()`, `globalThis.eval()` |
| `dangerous-new-function` | Injection | `critical` | Dynamic code compilation via `new Function(...)` |
| `dangerous-exec-template` | Injection | `critical` | `exec()` / `execSync()` called with template-literal interpolation |
| `dangerous-inner-html` | Injection | `high` | `dangerouslySetInnerHTML` XSS sink |
| `dangerous-raw-sql` | Injection | `critical` | `SELECT`/`INSERT`/`UPDATE`/`DELETE` built via `${...}` or `+` concatenation |
| `debris-sensitive-log` | Debris | `high` | `console.*` logging references to tokens, passwords, secrets, or keys |
| `debris-placeholder` | Debris | `medium` | Leftover `TODO: implement` or `FIXME` comments (blocking under `--strict`) |

Deleted files, binary files, and dependency lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `go.sum`, `*.lock`, etc.) are automatically skipped.

## Inline Suppression

Suppress intentional lines (or any line inside a multi-line empty `catch`/`except` block) with `// safe-vibe-ignore` or `# safe-vibe-ignore`:

```js
const legacy = eval(trustedBundle); // safe-vibe-ignore
```

```python
try:
    optional_cleanup()
except OSError: # safe-vibe-ignore
    pass
```

## License

MIT
