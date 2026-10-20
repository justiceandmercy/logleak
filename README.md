# logleak

Find `log`, `print`, and `console.*` statements that reference secrets or PII,
so you can stop leaking credentials into your logs.

## Features

- Zero runtime dependencies (Python 3.9+ standard library only).
- Scans Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, Kotlin, Rust, Swift.
- Detects 25+ sensitive terms: passwords, tokens, API keys, SSNs, credit cards, session IDs, cookies, JWTs, etc.
- Supports common loggers: `console.*`, `logger.*`, `logging.*`, `print`, `System.out.print*`.
- Text and JSON output; optional non-zero exit code for CI.

## Install

```bash
pip install -e .
```

Or run directly:

```bash
python -m logleak .
```

## Usage

Scan the current directory:

```bash
logleak .
```

Scan a specific folder and emit JSON:

```bash
logleak ./src --json
```

Fail CI when leaks exist:

```bash
logleak . --exit-code
```

## Example output

```
Found 2 potential leak(s):
  src/auth.py:14  (password)  logger.info("login ok for %s password=%s", user, password)
  src/api.js:8    (token)    console.log("debug token:", token)
```

## How it works

1. Walks the project, skipping heavy/generated directories.
2. For each source file, scans line by line.
3. If a line contains a logging/print call AND a sensitive term, it is reported.
4. Comment lines are skipped.

## Limitations

- Line-based heuristic: multi-line log calls and indirect leaks (logging an object that contains secrets) may be missed.
- May produce false positives when a sensitive word appears in a harmless message string.
- Use `--json` and post-filter in CI if needed.

## License

MIT