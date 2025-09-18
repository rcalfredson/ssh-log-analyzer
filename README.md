# SSH Log Analyzer

[![CI](https://github.com/rcalfredson/ssh-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/rcalfredson/ssh-log-analyzer/actions/workflows/ci.yml)

A small, readable Python tool that parses Linux SSH logs (e.g., `/var/log/auth.log`) to spot failed logins, brute-force attempts, invalid users, and success-after-many-fails patterns. Outputs human-friendly summaries to the terminal, plus optional CSV/HTML reports.

> Purpose: demonstrate practical security monitoring skills with clean code and clear documentation.

---

## Features

- Parses common OpenSSH log lines: `Failed password`, `Invalid user`, `Accepted password`, `session opened/closed`.
- Counts failures by IP/user and within a time window.
- Flags **brute force** (N failures in T minutes) and **invalid-user sprays**.
- Highlights **success after many failures** (potential compromise signal).
- Output formats: **terminal table**, **CSV**, and **HTML** (lightweight template).
- Ships with a small **sample log** so reviewers can run it immediately.
- Optional IP **geo-lookup** (e.g., ipinfo) when you provide an API token.

---

## Repository Layout

```
ssh-log-analyzer/
├─ src/sshlog/
│  ├─ __init__.py
│  ├─ parser.py        # regex + normalization for log events
│  ├─ detect.py        # detection rules (brute force, invalid user bursts, etc.)
│  ├─ report.py        # CLI/CSV/HTML reporting helpers (Rich + Jinja2)
│  └─ cli.py           # argparse + main() entrypoint
├─ samples/
│  └─ auth.sample.log  # tiny example log for quick demos
├─ tests/
│  └─ test_parser.py   # a couple of sanity tests
├─ out/                # generated artifacts (gitignored)
├─ requirements.txt
├─ README.md
└─ LICENSE
```

---

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**requirements.txt (suggested)**

```
pandas
python-dateutil
rich
jinja2
```

> Optional for geo-lookup: use an API such as ipinfo and export `IPINFO_TOKEN`.

---

## Usage

Analyze the included sample log and write CSV/HTML reports:

```bash
python -m sshlog.cli \
  --log samples/auth.sample.log \
  --threshold 5 \
  --window 10m \
  --csv out/report.csv \
  --html out/report.html
```

**Key flags**

- `--log`: path to a log file (repeatable).
- `--threshold`: failures per IP to flag brute force (default: `5`).
- `--window`: rolling time window (e.g., `10m`, `1h`).
- `--csv` / `--html`: optional output file paths.
- `--geo ipinfo`: enable IP geo-lookup with `IPINFO_TOKEN` set.

If you omit `--csv` and `--html`, the tool prints a formatted table to the terminal.

---

## What It Detects

1. **Brute Force**  
   ≥ *threshold* failed logins within *window* from the same IP → flag.

2. **Invalid User Spray**  
   Many `Invalid user` lines from one source in *window* → flag.

3. **Success After Many Fails**  
   An `Accepted password` following ≥X failures for that IP/user → highlight.

All rules live in `src/sshlog/detect.py` and are easy to tweak.

---

## Example Output (terminal)

```
Top sources (failed logins)
┏━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ IP           ┃ Fails┃ First Seen         ┃ Last Seen          ┃
┡━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ 203.0.113.5  │  24  │ 2025-08-24 01:11   │ 2025-08-24 01:22   │  ← BRUTE FORCE
│ 198.51.100.9 │  11  │ 2025-08-24 03:02   │ 2025-08-24 03:06   │
└──────────────┴──────┴────────────────────┴────────────────────┘
```

The HTML report provides sortable tables and simple highlighting for alerts.

---

## Sample Lines Covered

```
Jan 10 12:34:56 host sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
Jan 10 12:35:00 host sshd[12345]: Failed password for root from 203.0.113.5 port 54322 ssh2
Jan 10 12:35:10 host sshd[12345]: Accepted password for bob from 198.51.100.9 port 51515 ssh2
```

---

## Development

Run tests:

```bash
pytest -q
```

Format/lint (optional):

```bash
ruff check . && ruff format .
```

---

## Roadmap

- Whitelist/ignore private ranges (10.0.0.0/8, etc.).
- Group by ASN/country when geo is enabled.
- JSON export for SIEM ingestion.
- Dockerfile for one-shot runs.

---

## Safety & Ethics

Analyze your **own** systems or the provided sample logs. Do not process or probe systems without explicit authorization.

---

## License

MIT — free to use and adapt.
