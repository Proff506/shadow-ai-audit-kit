# Shadow AI Audit Kit

**Find out which AI tools are actually being used on a machine — in minutes, from a USB stick.**

Your staff are using AI tools you don't know about. Client files pasted into
chatbots. Customer data in prompts. A browser history full of services your
policies never approved. This kit answers the question every business owner
should be asking: *what is actually happening on our machines?*

Plug in the USB stick (or clone this repo), run one script, and get a
risk-ranked report of AI-tool usage across browsers, installed software, and
DNS logs. No cloud dependency. No telemetry. Nothing leaves the machine.

Built and field-tested by [elect-rix Technology Solutions](https://elect-rix.tech)
for professional Shadow AI Discovery audits. Released open-source so you can
verify exactly what it does — and run it yourself.

## What it finds

- **Browser history** — visits to 80+ known AI services (ChatGPT, Claude,
  Gemini, Copilot, Grok, DeepSeek, Perplexity, and more), with visit counts
  and timestamps. Chrome, Edge, Firefox, Brave, Arc, Safari, Chromium —
  including Linux snap/flatpak profiles.
- **Installed software** — AI desktop apps and AI-enabled tools (dpkg/rpm on
  Linux, registry inventory via PowerShell on Windows, /Applications on macOS).
- **DNS logs** — Pi-hole, OPNsense, dnsmasq, or syslog query logs matched
  against the AI domain watchlist.
- **Risk ranking** — every finding scored CRITICAL/HIGH/MEDIUM/LOW, with a
  PIPEDA/PHIPA exposure flag for Canadian privacy compliance.

## Output

Each scan produces an audit-evidence package:

| File | Purpose |
|------|---------|
| `report.html` | Branded, print-ready findings report |
| `report.pdf` | PDF version (when WeasyPrint is available) |
| `report.json` | Structured findings for tooling |
| `inventory.csv` | Flat spreadsheet of findings |
| `findings.db` | SQLite database of findings |
| `machine_info.json` | Host metadata (hostname, user, OS) |
| `scanner.log` | Timestamped activity log — the audit trail |

## Quick start

**Windows:** double-click `run.bat` (or `run.bat --express --client "Acme Corp"`).
No Python installation required — the kit can run from a bundled portable
Python on a USB stick.

**macOS:** double-click `run.command`, or `bash run.sh` in Terminal.
Note: Safari history requires Full Disk Access for your terminal — the
scanner detects this and tells you exactly what to grant instead of crashing.

**Linux:** `bash run.sh` or `python3 audit-kit.py`.

Two modes:

- **Wizard** (default) — interactive 5-step flow: client info, scan mode,
  output location, confirm, run. This is the field-audit experience.
- **Express** — `./audit-kit.py --express --client "Acme" --auditor "Jane"`.
  No prompts; auto-detects everything.
- **Dry run** — `./audit-kit.py --dry-run`. Lists every file and directory
  the scanner *would* read on this machine, then exits without reading
  anything. Use it to confirm scope with the client before touching data
  on privacy-sensitive engagements (PIPEDA/PHIPA).

Targeted scans via environment variables:
`AUDITKIT_SKIP_BROWSER=1` or `AUDITKIT_SKIP_SOFTWARE=1`.

## The watchlist

`ai_domains.json` is the curated AI-service watchlist — the single source of
truth for what counts as a finding. Entries carry a default risk level,
category, and recommended action. **PRs welcome**: new AI services launch
weekly, and keeping this list current is a community job. Entries with
`scan: false` are infrastructure/cloud domains tracked for reference but not
reported as Shadow AI findings.

## Tests

```
python3 -m pytest tests/ -v
```

27 tests covering the domain matcher, software inventory parsers, browser
path detection (including snap and Windows Store-stub edge cases), and
regressions from real field runs. `tests/fixtures-browser-matrix/` carries
synthetic Chrome/Edge/Brave/Firefox history databases (plus a Safari
fixture) used for cross-browser regression runs on all three platforms.

## Building standalone binaries

The kit can ship as a single-file executable (no Python needed on the target):

```
pip install pyinstaller
pyinstaller scanner.spec
```

Cross-platform binaries built and verified live from this code:
Linux x64, Windows 11 x64 (QEMU/KVM), and macOS arm64 (26.3) — see
`scanner.spec` for the build recipe.

## Run it yourself — or hire us

This kit is the same tool elect-rix uses on paid Shadow AI Discovery audits.
Running it yourself gives you the data. A professional audit gives you the
interpretation, the remediation roadmap, the staff policy templates, and a
report your insurer and counsel will accept.

**elect-rix Technology Solutions** — sovereign AI infrastructure for Canadian
business. Your data stays in your building.

- Web: [elect-rix.tech](https://elect-rix.tech)
- Phone: (506) 801-2722
- New Brunswick, Canada

## License

MIT (see LICENSE). Code and watchlist are free to use, fork, and extend.
The elect-rix name and branding are trademarks of RixBot Technologies Inc.
and not licensed for commercial reuse — rebrand the report template if you
redistribute.
