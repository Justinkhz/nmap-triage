# nmap-triage

**Parse and risk-rank Nmap XML output — CVE scoring, attack paths, and HTML reports**

A vulnerability triage tool for Nmap scans. Point it at an XML scan file and it scores every host by real risk, extracts CVEs and CVSS scores from NSE script output, detects dangerous service combinations, correlates findings across hosts, and produces a ranked report in your terminal, as HTML, or as JSON.

Zero dependencies. Pure Python stdlib. Works with any Nmap XML output.

---

![Python](https://img.shields.io/badge/python-3.10%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

---

## Features

- **CVSS-based scoring** — extracts real CVE IDs and CVSS scores from NSE script output (`vulners`, `vuln`). Score drives risk tier, not guesswork.
- **5-tier risk system** — CRITICAL / HIGH / MEDIUM / LOW / INFO with confidence flagging when no version data is available
- **Attack path detection** — identifies dangerous service combinations (SMB+RDP, exposed Docker API, Kubelet, Redis, Jupyter etc) and suggests ready-to-run commands
- **Cross-host correlation** — finds shared vulnerable versions, same high-risk ports across multiple hosts, and pivot targets
- **Graceful degradation** — works with a basic `-sS` scan using port heuristics, gets progressively better as you add `-sV`, `--script vulners`, and `-p-`
- **HTML report** — self-contained dark-themed report with CVSS bars, CVE pills, and attack path cards
- **JSON export** — structured output for SIEM ingestion, pipelines, or further processing
- **Filter flags** — `--only-high`, `--only-exploitable`, `--min-cvss`

---

## Quick Start

```bash
# Run against a scan file
python nmap_triage.py scan.xml

# With HTML report and JSON export
python nmap_triage.py scan.xml --html report.html --json out.json

# Test it without a scan file
python nmap_triage.py --demo
```

---

## Recommended Scan Commands

The tool works with any Nmap XML output. The more scan flags you use, the better the output:

```bash
# Minimum — port heuristics only, no version data
nmap -sS -oX scan.xml <target>

# Better — enables version matching and service patterns
nmap -sS -sV -oX scan.xml <target>

# Good — adds real CVE IDs and CVSS scores via vulners
nmap -sS -sV --script vulners -oX scan.xml <target>

# Best — full coverage, all ports, all scripts
nmap -p- -sV -sC --script vuln,vulners -oX scan.xml <target>
```

> **Note:** Without `-p-`, Nmap only scans the top 1000 ports by default. Services like Redis (6379), MongoDB (27017), and Elasticsearch (9200) sit above that range and will be silently missed. `-p-` is the single most impactful flag for complete coverage.

---

## Usage

```
python nmap_triage.py [input] [options]
```

| Argument | Description |
|---|---|
| `input` | Nmap XML file (produced with `-oX` or `-oA`) |
| `--top N` | Show top N hosts sorted by risk score (default: 20) |
| `--html FILE` | Write HTML report to FILE |
| `--json FILE` | Write JSON export to FILE |
| `--only-high` | Show CRITICAL and HIGH hosts only |
| `--only-exploitable` | Show hosts with confirmed exploitable CVEs only |
| `--min-cvss N` | Show hosts with at least one finding at CVSS >= N |
| `--demo` | Run with built-in demo data — no scan file needed |

### Examples

```bash
# Top 10 hosts, terminal only
python nmap_triage.py scan.xml --top 10

# Full output — HTML report, JSON export, critical/high only
python nmap_triage.py scan.xml --html report.html --json out.json --only-high

# Filter to confirmed exploitable findings only
python nmap_triage.py scan.xml --only-exploitable

# Filter to CVSS 7.0 and above
python nmap_triage.py scan.xml --min-cvss 7.0

# Demo mode — see what the output looks like without running a scan
python nmap_triage.py --demo --html demo.html
```

---

## How Scoring Works

Risk assessment runs in layers, using the best available data from the scan:

### 1. NSE CVE data (highest priority)
When the scan includes `--script vulners` or `--script vuln`, CVE IDs and CVSS scores are parsed directly from script output. CVSS maps to risk tier and overrides everything else.

### 2. Service pattern matching
Regex patterns matched against detected product and version strings. Covers known vulnerable versions including vsftpd 2.3.4 backdoor, Apache 2.4.49 path traversal, OpenSSL Heartbleed, Samba SambaCry, IIS 6.0 WebDAV RCE, PHP EOL versions, and more.

### 3. Port heuristics (fallback)
When no version data is available, risk is assessed by port number. 60+ ports are mapped with context-specific reasoning.

### 4. Confidence flagging
Ports with no detected version string are downgraded one tier and flagged `[no version]` so findings based on inference are clearly distinguished from evidence-backed findings.

### Risk tiers

| Tier | CVSS | Meaning |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | Confirmed RCE, backdoor, or unauthenticated full access |
| HIGH | 7.0 – 8.9 | Serious exposure, likely exploitable |
| MEDIUM | 4.0 – 6.9 | Meaningful risk, warrants investigation |
| LOW | 0.1 – 3.9 | Low impact or low exploitability |
| INFO | — | Informational — ephemeral ports, closed services |
| UNKNOWN | — | No data — manual investigation needed |

---

## Attack Path Detection

The tool checks every host for dangerous service combinations and generates operator-ready hints with actual commands:

| Combo | Risk | Hint |
|---|---|---|
| SMB (445) + RDP (3389) | HIGH | NTLM relay + GUI access — crackmapexec, impacket |
| SMB + NetBIOS + MSRPC | CRITICAL | Full Windows attack surface — EternalBlue, relay attacks |
| Docker API (2375) | CRITICAL | Unauthenticated API — privileged container for host takeover |
| Kubelet (10250) | CRITICAL | Pod exec, secret read, container escape |
| Redis (6379) | HIGH | Write SSH keys or cron for RCE |
| Elasticsearch (9200) | HIGH | No-auth default — full index dump |
| MongoDB (27017) | HIGH | No-auth default — full database read/write |
| Jupyter (8888) | HIGH | No-token default — arbitrary Python execution |
| VNC (5900) | HIGH | Often no/weak auth — full desktop access |
| SNMP (161) | HIGH | Default community strings — full system info disclosure |
| IPMI (623) | HIGH | Cipher 0 auth bypass or hash disclosure |

All commands shown in attack path output have the target IP substituted in automatically.

---

## Cross-Host Correlation

After scoring individual hosts, the tool analyses the full scan for:

- **Shared versions** — same product and version running on multiple hosts. Patch one, patch all.
- **Shared high-risk ports** — same dangerous port open across multiple machines
- **Pivot targets** — hosts with both a database/cache service and remote access, ideal for lateral movement

---

## Output Formats

### Terminal
Colour-coded ANSI output. Risk tiers in magenta/red/yellow/green. CVE IDs, CVSS scores, NSE script snippets, attack paths, and tool commands inline.

### HTML (`--html`)
Self-contained dark-themed report. CVSS bar charts per port, CVE pills, attack path cards, correlation table. No server needed — open directly in a browser.

### JSON (`--json`)
Full structured export for automation, SIEM ingestion, or pipeline processing.

```bash
# Example jq queries against JSON output

# All CRITICAL hosts
cat out.json | jq '.hosts[] | select(.risk_level=="CRITICAL") | .ip'

# All CVEs found across the scan
cat out.json | jq '.hosts[].ports[].cves[].id'

# Exploitable findings only
cat out.json | jq '.hosts[].ports[] | select(.has_exploit==true) | {port, service, cves}'
```

---

## Requirements

- Python 3.10+
- No third-party packages — stdlib only

---

## Tips

**Use `-p-` for complete coverage**
Without it you only scan the top 1000 ports. Most database and infrastructure services sit above that range and will be silently missed.

**Two-phase scanning on large networks**
A full `-p- -sV --script vuln,vulners` scan against a /24 takes time. Run a fast SYN scan first to find live hosts and open ports, then run version detection and scripts targeted at only the interesting results.

```bash
# Phase 1 — fast discovery
nmap -sS -p- --min-rate 5000 -oX discovery.xml 192.168.1.0/24

# Phase 2 — targeted deep scan on interesting hosts
nmap -sV -sC --script vuln,vulners -oX deep.xml 192.168.1.10 192.168.1.25
```

**Interpreting `[no version]`**
A `[no version]` flag means the risk rating is based on port number alone. The actual service may differ from what Nmap assumes — treat these as leads for manual investigation rather than confirmed findings.

**`--only-exploitable` for fast triage**
On a large scan, start with `--only-exploitable` to surface the highest-confidence findings first, then work outward to `--only-high` and the full output.

---

## Disclaimer

This tool is intended for use on networks and systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions.

---

## License

MIT — see [LICENSE](LICENSE)
