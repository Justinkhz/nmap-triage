# nmap-triage

**Parse and risk-rank Nmap XML output — CVE scoring, misconfig detection, attack paths, and HTML reports**

A vulnerability triage tool for Nmap scans. Point it at an XML scan file and it scores every host by real risk, extracts CVEs and CVSS scores from NSE script output, flags known misconfigurations, detects dangerous service combinations, correlates findings across hosts, and produces a ranked report in your terminal, as HTML, or as JSON.

Zero dependencies. Pure Python stdlib.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Quick Start

```bash
python nmap_triage.py scan.xml
python nmap_triage.py scan.xml --html report.html --json out.json
python nmap_triage.py --demo
```

> Works with any Nmap XML output (`-oX` or `-oA`). The more scan flags you use (`-sV`, `-p-`, `--script vulners`), the more accurate the results — none are required.

---

## Usage

```
python nmap_triage.py [input] [options]
```

| Argument | Description |
|---|---|
| `input` | Nmap XML file |
| `--top N` | Show top N hosts sorted by risk score (default: 20) |
| `--html FILE` | Write HTML report to FILE |
| `--json FILE` | Write JSON export to FILE |
| `--merge FILE` | Merge in a second Nmap XML scan of the same network |
| `--only-high` | Show CRITICAL and HIGH hosts only |
| `--only-exploitable` | Show hosts with confirmed exploitable CVEs only |
| `--min-cvss N` | Show hosts with at least one finding at CVSS >= N |
| `--demo` | Run with built-in demo data — no scan file needed |

---

## How it works

Risk is assessed in layers, using the best available evidence: real CVE/CVSS data from NSE scripts (`vulners`, `vuln`) first, then known misconfiguration signatures (anonymous FTP, SMB signing disabled, unauthenticated Redis/MongoDB/Docker, open relays, default creds — shown separately from CVEs since they're settings, not software bugs), then version-pattern matching against known vulnerable builds, then port-number heuristics as a fallback. Ports with no detected version are downgraded and flagged `[no version]` so inferred risk is never confused with evidence-backed risk.

On top of per-port scoring, the tool checks each host for dangerous service combinations (SMB+RDP, an exposed Docker API, Redis with no auth, etc.) and surfaces ready-to-run commands for each, then looks across the whole scan for shared vulnerable versions, shared high-risk ports, and hosts that make good pivot targets.

---

## Merging scans

`--merge` combines two Nmap XML files into one report — useful for a fast `-sS` sweep followed by a slower `-p- -sV -sC` deep scan:

```bash
nmap -sS -p- --min-rate 5000 -oX fast.xml 10.0.0.0/24
nmap -sV -sC --script vuln,vulners -oX deep.xml 10.0.0.5 10.0.0.20

python nmap_triage.py fast.xml --merge deep.xml
```

Hosts are matched by IP; ports are unioned, keeping whichever scan's result carries more evidence. Risk scores and attack paths are recalculated on the merged result.

---

## Output formats

- **Terminal** — colour-coded, with CVEs, misconfigs, attack paths and commands inline.
- **HTML** (`--html`) — self-contained dark-themed report with a live search box filtering by IP, hostname, port, or service. No server needed.
- **JSON** (`--json`) — structured export for pipelines or SIEM ingestion.

---

## Notes

- `-p-` matters more than most flags — the default top-1000 scan misses most database/infra ports.
- `-sC` only covers two of the misconfig scripts (`ftp-anon`, `smb-security-mode`); the rest need to be named explicitly with `--script`.
- A `[no version]` flag means the risk rating is port-number-only — treat it as a lead, not a confirmed finding.

---

## Requirements

Python 3.10+, no third-party packages.

---

## Disclaimer

For use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal.

---

## License

MIT — see [LICENSE](LICENSE)
