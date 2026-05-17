# nmap-triage

**Parse and risk-rank Nmap XML output — CVE scoring, attack paths, and HTML reports**

A vulnerability triage tool for Nmap scans. Point it at an XML scan file and it scores every host by real risk, extracts CVEs and CVSS scores from NSE script output, detects dangerous service combinations, correlates findings across hosts, and produces a ranked report in your terminal, as HTML, or as JSON.

Zero dependencies. Pure Python stdlib.

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Quick Start

```bash
python nmap_triage.py scan.xml
python nmap_triage.py scan.xml --html report.html --json out.json
python nmap_triage.py --demo
```

> The tool works with any Nmap XML output (`-oX` or `-oA`). The more scan flags you use (e.g. `-sV`, `-p-`, `--script vulners`), the more accurate the results — but none are required.

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
| `--only-high` | Show CRITICAL and HIGH hosts only |
| `--only-exploitable` | Show hosts with confirmed exploitable CVEs only |
| `--min-cvss N` | Show hosts with at least one finding at CVSS >= N |
| `--demo` | Run with built-in demo data — no scan file needed |

---

## How Scoring Works

Risk assessment runs in layers, using the best available data:

1. **NSE CVE data** — CVE IDs and CVSS scores parsed directly from `vulners` / `vuln` script output. Takes highest priority.
2. **Service pattern matching** — regex matched against detected product and version strings. Covers known vulnerable versions (vsftpd 2.3.4, Apache 2.4.49, OpenSSL Heartbleed, Samba, IIS 6.0, and more).
3. **Port heuristics** — fallback when no version data is available. 60+ ports mapped with context-specific reasoning.
4. **Confidence flagging** — ports with no detected version are downgraded one tier and flagged `[no version]`.

### Risk Tiers

| Tier | CVSS | Meaning |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | Confirmed RCE, backdoor, or unauthenticated full access |
| HIGH | 7.0 – 8.9 | Serious exposure, likely exploitable |
| MEDIUM | 4.0 – 6.9 | Warrants investigation |
| LOW | 0.1 – 3.9 | Low impact or low exploitability |
| INFO | — | Ephemeral ports, closed services |
| UNKNOWN | — | No data — manual investigation needed |

---

## Attack Path Detection

Checks every host for dangerous service combinations and generates operator-ready hints with commands. Examples:

| Combo | Risk | Action |
|---|---|---|
| SMB (445) + RDP (3389) | HIGH | NTLM relay + GUI access |
| SMB + NetBIOS + MSRPC | CRITICAL | Full Windows attack surface |
| Docker API (2375) | CRITICAL | Unauthenticated — privileged container for host takeover |
| Kubelet (10250) | CRITICAL | Pod exec, secret read, container escape |
| Redis (6379) | HIGH | Write SSH keys or cron for RCE |
| Elasticsearch (9200) | HIGH | No-auth default — full index dump |
| Jupyter (8888) | HIGH | No-token default — arbitrary Python execution |

Commands in attack path output have the target IP substituted in automatically.

---

## Cross-Host Correlation

After scoring individual hosts, the tool analyses the full scan for:

- **Shared versions** — same product/version on multiple hosts
- **Shared high-risk ports** — same dangerous port across multiple machines
- **Pivot targets** — hosts combining database/cache services with remote access

---

## Output Formats

**Terminal** — colour-coded ANSI output with CVE IDs, CVSS scores, NSE script snippets, attack paths, and tool commands inline.

**HTML** (`--html`) — self-contained dark-themed report with CVSS bars, CVE pills, and attack path cards. Open directly in any browser.

**JSON** (`--json`) — full structured export for automation, SIEM ingestion, or pipeline processing.

```bash
# Useful jq queries
cat out.json | jq '.hosts[] | select(.risk_level=="CRITICAL") | .ip'
cat out.json | jq '.hosts[].ports[] | select(.has_exploit==true) | {port, service, cves}'
```

---

## Requirements

- Python 3.10+
- No third-party packages — stdlib only

---

## Disclaimer

This tool is intended for use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal.

---

## License

MIT — see [LICENSE](LICENSE)
