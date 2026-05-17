#!/usr/bin/env python3
"""
nmap_triage — Nmap Vulnerability Triage Tool
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Recommended scan command:
  nmap -p- -sV -sC --script vuln,vulners -oX scan.xml <target>

Usage:
  python nmap_triage.py scan.xml
  python nmap_triage.py scan.xml --top 15 --html report.html --json out.json
  python nmap_triage.py --demo
  python nmap_triage.py scan.xml --only-high
  python nmap_triage.py scan.xml --min-cvss 7.0
  python nmap_triage.py scan.xml --only-exploitable
"""

import argparse
import json
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & LOOKUP TABLES
# ══════════════════════════════════════════════════════════════════════════════

RISK_ORDER   = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}
RISK_COLOUR  = {
    "CRITICAL": "\033[95m",  # magenta
    "HIGH":     "\033[91m",  # red
    "MEDIUM":   "\033[93m",  # yellow
    "LOW":      "\033[92m",  # green
    "INFO":     "\033[96m",  # cyan
    "UNKNOWN":  "\033[90m",  # dark grey
}
RESET = "\033[0m";  BOLD = "\033[1m";  DIM = "\033[2m";  CYAN = "\033[96m"

# Port → (base_risk, reason)
PORT_INTEL = {
    21:    ("HIGH",     "FTP — plaintext credentials, often anonymous access"),
    22:    ("MEDIUM",   "SSH — brute-force surface; version determines real risk"),
    23:    ("HIGH",     "Telnet — plaintext, no encryption"),
    25:    ("MEDIUM",   "SMTP — relay abuse / user enumeration"),
    53:    ("LOW",      "DNS — zone transfer / amplification risk"),
    69:    ("HIGH",     "TFTP — unauthenticated file read/write"),
    79:    ("MEDIUM",   "Finger — user enumeration"),
    80:    ("MEDIUM",   "HTTP — web attack surface"),
    88:    ("MEDIUM",   "Kerberos — ticket attacks (AS-REP Roasting, Kerberoasting)"),
    110:   ("MEDIUM",   "POP3 — plaintext mail credentials"),
    111:   ("MEDIUM",   "RPCbind — exposes RPC services"),
    135:   ("HIGH",     "MSRPC — Windows RPC exploit surface (MS03-026 etc)"),
    139:   ("HIGH",     "NetBIOS — credential relay, enumeration"),
    143:   ("MEDIUM",   "IMAP — plaintext mail credentials"),
    161:   ("HIGH",     "SNMP — default community strings, info disclosure"),
    162:   ("MEDIUM",   "SNMP trap — receiver exposure"),
    389:   ("MEDIUM",   "LDAP — directory enumeration / credential spray"),
    443:   ("LOW",      "HTTPS — check TLS version and web app"),
    445:   ("HIGH",     "SMB — EternalBlue, relay attacks, ransomware vector"),
    512:   ("HIGH",     "rexec — plaintext remote execution"),
    513:   ("HIGH",     "rlogin — trust-based auth"),
    514:   ("HIGH",     "rsh — unauthenticated remote shell"),
    554:   ("LOW",      "RTSP — media stream, possible auth bypass"),
    587:   ("LOW",      "SMTP submission — check auth"),
    593:   ("HIGH",     "HTTP RPC — DCOM over HTTP exploit surface"),
    623:   ("HIGH",     "IPMI — often default/no auth, plaintext, hash disclosure"),
    631:   ("MEDIUM",   "IPP/CUPS — printer exploit history"),
    873:   ("HIGH",     "rsync — often unauthenticated"),
    902:   ("MEDIUM",   "VMware ESXi — check for auth"),
    1080:  ("HIGH",     "SOCKS proxy — open proxy / pivot"),
    1099:  ("HIGH",     "Java RMI — remote code execution"),
    1433:  ("HIGH",     "MSSQL — xp_cmdshell, database exposure"),
    1521:  ("HIGH",     "Oracle DB — TNS listener attacks"),
    1723:  ("MEDIUM",   "PPTP VPN — weak encryption"),
    2049:  ("HIGH",     "NFS — unauthenticated mount possible"),
    2181:  ("HIGH",     "ZooKeeper — unauthenticated by default"),
    2375:  ("CRITICAL", "Docker API (plain) — full host takeover"),
    2376:  ("MEDIUM",   "Docker TLS — check cert validation"),
    3000:  ("MEDIUM",   "Grafana/dev web — check for default creds"),
    3306:  ("HIGH",     "MySQL — database exposure"),
    3389:  ("HIGH",     "RDP — BlueKeep, brute-force, credential intercept"),
    4369:  ("HIGH",     "RabbitMQ/Erlang epmd — cluster pivot risk"),
    4444:  ("CRITICAL", "Metasploit default listener — likely active backdoor"),
    4505:  ("HIGH",     "SaltStack — CVE-2020-11651 RCE"),
    4848:  ("HIGH",     "GlassFish admin — default creds, RCE"),
    5000:  ("MEDIUM",   "Docker registry / Flask dev server"),
    5432:  ("HIGH",     "PostgreSQL — database exposure"),
    5672:  ("MEDIUM",   "AMQP/RabbitMQ — default creds common"),
    5900:  ("HIGH",     "VNC — often no/weak auth"),
    5985:  ("MEDIUM",   "WinRM HTTP — PowerShell remoting"),
    5986:  ("MEDIUM",   "WinRM HTTPS — PowerShell remoting"),
    6379:  ("HIGH",     "Redis — unauthenticated by default, RCE via config write"),
    7001:  ("HIGH",     "WebLogic — serial RCE CVEs, default creds"),
    7077:  ("HIGH",     "Apache Spark master — unauthenticated RCE"),
    8080:  ("MEDIUM",   "HTTP alt — admin panels often exposed here"),
    8443:  ("MEDIUM",   "HTTPS alt — check TLS and app"),
    8888:  ("HIGH",     "Jupyter Notebook — often no auth, RCE via code exec"),
    9000:  ("MEDIUM",   "PHP-FPM / SonarQube — check auth"),
    9090:  ("MEDIUM",   "Prometheus — metrics exposure, often no auth"),
    9200:  ("HIGH",     "Elasticsearch — unauthenticated, data exposure"),
    9300:  ("HIGH",     "Elasticsearch cluster — node exposure"),
    10250: ("CRITICAL", "Kubelet API — container escape / RCE"),
    27017: ("HIGH",     "MongoDB — unauthenticated by default"),
    50070: ("HIGH",     "Hadoop NameNode — unauthenticated RCE"),
}

# Regex patterns → (risk, CVE hint, reason)  (applied to normalised service string)
SERVICE_PATTERNS = [
    # Known backdoors / RCE
    (re.compile(r"vsftpd\s*2\.3\.4",         re.I), "CRITICAL", "CVE-2011-2523", "vsftpd 2.3.4 backdoor — instant shell"),
    (re.compile(r"unreal\s*ircd",             re.I), "CRITICAL", "CVE-2010-2075", "UnrealIRCd backdoor — remote shell"),
    (re.compile(r"distccd",                   re.I), "CRITICAL", "CVE-2004-2687", "distccd RCE — unauthenticated code exec"),
    (re.compile(r"proftpd\s*1\.3\.3",         re.I), "HIGH",     "CVE-2010-4221", "ProFTPD 1.3.3 — remote code execution"),

    # Apache
    (re.compile(r"apache.*(2\.4\.49)",        re.I), "CRITICAL", "CVE-2021-41773", "Apache 2.4.49 path traversal / RCE"),
    (re.compile(r"apache.*(2\.4\.50)",        re.I), "CRITICAL", "CVE-2021-42013", "Apache 2.4.50 path traversal / RCE"),
    (re.compile(r"apache.*2\.2\.",            re.I), "HIGH",     "EOL",            "Apache 2.2.x — end-of-life, multiple CVEs"),
    (re.compile(r"apache.*2\.4\.[0-3][0-9]", re.I), "MEDIUM",   "",               "Apache 2.4 older — check specific CVEs"),

    # IIS
    (re.compile(r"iis[/ ]*6\.0",             re.I), "CRITICAL", "CVE-2017-7269", "IIS 6.0 WebDAV buffer overflow RCE"),
    (re.compile(r"iis[/ ]*5\.",              re.I), "HIGH",     "EOL",           "IIS 5.x — EOL, extensive CVE history"),

    # OpenSSL / Heartbleed
    (re.compile(r"openssl\s*1\.0\.1[a-f]?",  re.I), "CRITICAL", "CVE-2014-0160", "Heartbleed — private key disclosure"),
    (re.compile(r"openssl\s*1\.0\.[012]",    re.I), "HIGH",     "EOL",           "OpenSSL 1.0.x — EOL, multiple CVEs"),

    # PHP
    (re.compile(r"php[/ ]*5\.",              re.I), "HIGH",     "EOL",           "PHP 5.x — EOL, many unpatched CVEs"),
    (re.compile(r"php[/ ]*7\.[012]\.",       re.I), "MEDIUM",   "EOL",           "PHP 7.0-7.2 — EOL"),

    # SSH
    (re.compile(r"openssh\s*[1-6]\.",        re.I), "HIGH",     "",              "OpenSSH < 7 — multiple auth CVEs"),
    (re.compile(r"openssh\s*7\.",            re.I), "LOW",      "CVE-2018-15473","OpenSSH 7.x — user enum CVE-2018-15473"),

    # Samba / SMB
    (re.compile(r"samba\s*[23]\.",           re.I), "HIGH",     "CVE-2017-7494", "Samba 2/3.x — SambaCry RCE possible"),
    (re.compile(r"samba\s*4\.[0-7]\.",       re.I), "MEDIUM",   "",              "Samba 4.x older — check CVEs"),

    # Databases
    (re.compile(r"ms\s*sql.*2000",           re.I), "CRITICAL", "EOL",           "MSSQL 2000 — EOL, many RCE CVEs"),
    (re.compile(r"mysql\s*[34]\.",           re.I), "HIGH",     "EOL",           "MySQL 3/4 — EOL, known exploits"),

    # Log4Shell indicator
    (re.compile(r"elasticsearch|solr|vmware|spring", re.I), "MEDIUM", "CVE-2021-44228", "Log4j dependency likely — check for Log4Shell"),

    # Other
    (re.compile(r"telnet",                   re.I), "HIGH",     "",              "Telnet — plaintext credentials"),
    (re.compile(r"vnc",                      re.I), "HIGH",     "CVE-2006-2369", "VNC — check for auth bypass"),
    (re.compile(r"weblogic",                 re.I), "HIGH",     "CVE-2020-14882","WebLogic — serial/RCE CVE history"),
    (re.compile(r"jboss|wildfly",            re.I), "HIGH",     "CVE-2017-12149","JBoss — deserialisation RCE"),
    (re.compile(r"tomcat",                   re.I), "MEDIUM",   "CVE-2020-1938", "Tomcat — AJP Ghostcat, check version"),
    (re.compile(r"jenkins",                  re.I), "HIGH",     "CVE-2024-23897","Jenkins — CLI file read / RCE CVE history"),
    (re.compile(r"gitlab",                   re.I), "MEDIUM",   "",              "GitLab — check version for RCE CVEs"),
    (re.compile(r"wordpress",               re.I),  "MEDIUM",   "",              "WordPress — plugin/theme attack surface"),
    (re.compile(r"drupal",                   re.I), "HIGH",     "CVE-2018-7600", "Drupal — Drupalgeddon RCE history"),
]

# Combo findings that bump host score
ATTACK_COMBOS = [
    {
        "ports": {445, 3389},
        "label": "SMB + RDP",
        "risk_bonus": 15,
        "risk": "HIGH",
        "hint": "Classic lateral movement pair — credential relay via SMB then RDP for GUI access",
        "tools": ["crackmapexec smb <ip>", "impacket-psexec domain/user@<ip>", "xfreerdp /v:<ip>"],
    },
    {
        "ports": {445, 139},
        "label": "SMB + NetBIOS",
        "risk_bonus": 10,
        "risk": "HIGH",
        "hint": "NetBIOS+SMB together — NTLM relay, pass-the-hash, enumeration",
        "tools": ["responder -I eth0", "impacket-ntlmrelayx -tf targets.txt", "enum4linux -a <ip>"],
    },
    {
        "ports": {22, 21},
        "label": "FTP + SSH",
        "risk_bonus": 8,
        "risk": "HIGH",
        "hint": "FTP may expose SSH keys or allow write to ~/.ssh/authorized_keys",
        "tools": ["ftp <ip>  (try anonymous)", "hydra -l root -P rockyou.txt ftp://<ip>"],
    },
    {
        "ports": {6379},
        "label": "Redis exposed",
        "risk_bonus": 12,
        "risk": "HIGH",
        "hint": "Redis without auth — write SSH keys or cron for RCE",
        "tools": ["redis-cli -h <ip> info", "redis-cli -h <ip> config set dir /root/.ssh/"],
    },
    {
        "ports": {9200},
        "label": "Elasticsearch exposed",
        "risk_bonus": 10,
        "risk": "HIGH",
        "hint": "Elasticsearch no-auth default — dump all indices for data exfil",
        "tools": ["curl http://<ip>:9200/_cat/indices", "curl http://<ip>:9200/_all/_search?size=100"],
    },
    {
        "ports": {27017},
        "label": "MongoDB exposed",
        "risk_bonus": 10,
        "risk": "HIGH",
        "hint": "MongoDB no-auth default — full database read/write",
        "tools": ["mongo <ip>:27017", "mongodump --host <ip> --out ./dump"],
    },
    {
        "ports": {2375},
        "label": "Docker API exposed",
        "risk_bonus": 20,
        "risk": "CRITICAL",
        "hint": "Unauth Docker API = full host takeover via privileged container",
        "tools": ["docker -H tcp://<ip>:2375 ps", "docker -H tcp://<ip>:2375 run --rm -v /:/mnt alpine ls /mnt"],
    },
    {
        "ports": {10250},
        "label": "Kubelet exposed",
        "risk_bonus": 20,
        "risk": "CRITICAL",
        "hint": "Kubelet API often unauthenticated — exec into pods, read secrets",
        "tools": ["curl -sk https://<ip>:10250/pods", "kubectl --server=https://<ip>:10250 exec -it <pod> -- sh"],
    },
    {
        "ports": {5900},
        "label": "VNC exposed",
        "risk_bonus": 12,
        "risk": "HIGH",
        "hint": "VNC often has weak/no auth — full desktop access",
        "tools": ["vncviewer <ip>:5900", "hydra -P rockyou.txt vnc://<ip>"],
    },
    {
        "ports": {161},
        "label": "SNMP exposed",
        "risk_bonus": 8,
        "risk": "HIGH",
        "hint": "SNMP v1/v2 default community strings leak full system info",
        "tools": ["snmpwalk -v2c -c public <ip>", "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <ip>"],
    },
    {
        "ports": {3389, 445, 135},
        "label": "Full Windows attack surface",
        "risk_bonus": 20,
        "risk": "CRITICAL",
        "hint": "RDP + SMB + RPC = full Windows pentest surface. Check for BlueKeep, EternalBlue, NTLM relay",
        "tools": ["nmap --script smb-vuln-* -p445 <ip>", "impacket-smbclient <ip>", "crackmapexec smb <ip> -u '' -p ''"],
    },
    {
        "ports": {8888},
        "label": "Jupyter Notebook",
        "risk_bonus": 15,
        "risk": "HIGH",
        "hint": "Jupyter often has no token auth — execute arbitrary Python = RCE",
        "tools": ["curl http://<ip>:8888/api/kernels", "open http://<ip>:8888 in browser"],
    },
    {
        "ports": {4444},
        "label": "Backdoor port open",
        "risk_bonus": 25,
        "risk": "CRITICAL",
        "hint": "Port 4444 is the Metasploit default — host may already be compromised",
        "tools": ["nc -nv <ip> 4444", "ncat <ip> 4444"],
    },
    {
        "ports": {623},
        "label": "IPMI exposed",
        "risk_bonus": 15,
        "risk": "HIGH",
        "hint": "IPMI v2.0 cipher 0 auth bypass or hash disclosure — leads to full server control",
        "tools": ["ipmitool -I lanplus -H <ip> -U admin -P admin chassis status",
                  "metasploit: use auxiliary/scanner/ipmi/ipmi_dumphashes"],
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CVEFinding:
    cve_id: str
    cvss: float
    exploitable: bool = False
    source: str = "NSE"


@dataclass
class ScriptFinding:
    script_id: str
    output: str
    cves: list = field(default_factory=list)   # list[CVEFinding]
    risk_level: str = "INFO"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str
    version: str
    extra_info: str
    conf: int = 0              # Nmap service detection confidence (0-10)
    scripts: list = field(default_factory=list)   # list[ScriptFinding]
    cves: list = field(default_factory=list)       # list[CVEFinding]
    risk_level: str = "UNKNOWN"
    risk_reason: str = ""
    max_cvss: float = 0.0
    has_exploit: bool = False
    version_confidence: str = "NONE"  # NONE, LOW, HIGH

    @property
    def full_service_str(self) -> str:
        parts = [self.service, self.product, self.version, self.extra_info]
        return " ".join(p for p in parts if p).strip() or "unknown"

    @property
    def open(self) -> bool:
        return self.state == "open"


@dataclass
class AttackPath:
    label: str
    risk: str
    hint: str
    tools: list
    ports: set


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    os_guess: str = ""
    os_confidence: int = 0
    mac: str = ""
    state: str = "up"
    ports: list = field(default_factory=list)
    attack_paths: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "LOW"
    cve_count: int = 0
    exploitable_count: int = 0

    @property
    def display_name(self) -> str:
        return self.ip + (f" ({self.hostname})" if self.hostname else "")

    @property
    def open_ports(self) -> list:
        return [p for p in self.ports if p.open]

    @property
    def open_port_numbers(self) -> set:
        return {p.port for p in self.open_ports}


# ══════════════════════════════════════════════════════════════════════════════
# XML PARSING
# ══════════════════════════════════════════════════════════════════════════════

def parse_nmap_xml(filepath: str) -> list:
    tree = ET.parse(filepath)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = hostname = mac = ""
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype", "")
            if atype in ("ipv4", "ipv6") and not ip:
                ip = addr.get("addr", "")
            elif atype == "mac":
                mac = addr.get("addr", "")

        for hn in host_el.findall("hostnames/hostname"):
            if hn.get("type") in ("PTR", "user"):
                hostname = hn.get("name", "")
                break

        os_guess, os_conf = "", 0
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            os_guess = os_el.get("name", "")
            os_conf  = int(os_el.get("accuracy", 0))

        host = HostInfo(ip=ip, hostname=hostname, os_guess=os_guess,
                        os_confidence=os_conf, mac=mac)

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""

            svc_el = port_el.find("service")
            service = product = version = extra = ""
            conf = 0
            if svc_el is not None:
                service = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                extra   = svc_el.get("extrainfo", "")
                conf    = int(svc_el.get("conf", 0))

            p = PortInfo(
                port=int(port_el.get("portid", 0)),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service=service, product=product, version=version,
                extra_info=extra, conf=conf,
                version_confidence="HIGH" if version else ("LOW" if service else "NONE"),
            )

            # Parse NSE scripts on this port
            for script_el in port_el.findall("script"):
                sf = parse_script(script_el)
                if sf:
                    p.scripts.append(sf)
                    p.cves.extend(sf.cves)
                    if sf.cves:
                        top = max(sf.cves, key=lambda c: c.cvss)
                        if top.cvss > p.max_cvss:
                            p.max_cvss = top.cvss
                        if top.exploitable:
                            p.has_exploit = True

            assess_port_risk(p)
            host.ports.append(p)

        # Host-level scripts (e.g. smb-vuln-* run at host level in some scans)
        for script_el in host_el.findall("hostscript/script"):
            sf = parse_script(script_el)
            if sf:
                for port in host.ports:
                    if port.port in (445, 139) and port.open:
                        port.scripts.append(sf)
                        port.cves.extend(sf.cves)

        detect_attack_paths(host)
        score_host(host)
        hosts.append(host)

    return hosts


def parse_script(script_el) -> ScriptFinding | None:
    sid    = script_el.get("id", "")
    output = script_el.get("output", "").strip()
    if not sid:
        return None

    sf = ScriptFinding(script_id=sid, output=output[:500])

    # Parse CVEs from vulners / vuln script output
    # Pattern: CVE-YYYY-NNNNN   CVSS: N.N  or  CVSSv2: N.N
    cve_pattern  = re.compile(r"(CVE-\d{4}-\d+)", re.I)
    cvss_pattern = re.compile(r"cvss(?:v\d)?[:\s]+(\d+\.?\d*)", re.I)
    exploit_pattern = re.compile(r"exploit|msf|metasploit|edb-id", re.I)

    # Try to parse table elements for structured vulners output
    cve_map: dict = {}
    for table in script_el.findall(".//table"):
        cve_id = cvss_val = ""
        is_exploit = False
        for elem in table.findall("elem"):
            key = elem.get("key", "").lower()
            val = (elem.text or "").strip()
            if key == "id" and re.match(r"CVE-", val, re.I):
                cve_id = val.upper()
            elif key == "cvss":
                try:
                    cvss_val = float(val)
                except ValueError:
                    pass
            elif key == "type" and "exploit" in val.lower():
                is_exploit = True
        if cve_id:
            cve_map[cve_id] = CVEFinding(cve_id=cve_id, cvss=float(cvss_val or 0),
                                          exploitable=is_exploit, source=sid)

    # Fallback: regex scan of raw output
    if not cve_map:
        for cve_match in cve_pattern.finditer(output):
            cid = cve_match.group(1).upper()
            if cid not in cve_map:
                # Try to find CVSS near this CVE in the output
                snippet = output[max(0, cve_match.start()-30):cve_match.end()+60]
                cvss_m  = cvss_pattern.search(snippet)
                cvss    = float(cvss_m.group(1)) if cvss_m else 0.0
                exploit = bool(exploit_pattern.search(snippet))
                cve_map[cid] = CVEFinding(cve_id=cid, cvss=cvss, exploitable=exploit, source=sid)

    sf.cves = list(cve_map.values())

    # Set script risk level from highest CVSS
    if sf.cves:
        top_cvss = max(c.cvss for c in sf.cves)
        sf.risk_level = cvss_to_risk(top_cvss)
    elif any(kw in output.lower() for kw in ["vulnerable", "exploit", "rce", "backdoor"]):
        sf.risk_level = "HIGH"
    elif any(kw in output.lower() for kw in ["warning", "weak", "deprecated"]):
        sf.risk_level = "MEDIUM"

    return sf


# ══════════════════════════════════════════════════════════════════════════════
# RISK ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════

def cvss_to_risk(cvss: float) -> str:
    if cvss >= 9.0:  return "CRITICAL"
    if cvss >= 7.0:  return "HIGH"
    if cvss >= 4.0:  return "MEDIUM"
    if cvss > 0:     return "LOW"
    return "UNKNOWN"


def assess_port_risk(p: PortInfo):
    if not p.open:
        p.risk_level = "INFO"
        p.risk_reason = f"Port {p.state}"
        return

    # 1. CVSS from NSE scripts takes highest priority
    if p.max_cvss >= 4.0:
        p.risk_level  = cvss_to_risk(p.max_cvss)
        top_cve       = max(p.cves, key=lambda c: c.cvss)
        p.risk_reason = f"NSE: {top_cve.cve_id} CVSS {p.max_cvss:.1f}" + (" [EXPLOIT AVAILABLE]" if p.has_exploit else "")
        return

    # 2. Regex service pattern matching
    svc_norm = re.sub(r"\s+", " ", p.full_service_str.lower())
    for pattern, risk, cve, reason in SERVICE_PATTERNS:
        if pattern.search(svc_norm):
            p.risk_level  = risk
            p.risk_reason = f"{reason}" + (f" ({cve})" if cve else "")
            # Downgrade if no version detected
            if p.version_confidence == "NONE" and RISK_ORDER[risk] >= RISK_ORDER["HIGH"]:
                p.risk_level  = "MEDIUM"
                p.risk_reason = f"[Low confidence — no version] {p.risk_reason}"
            return

    # 3. Port intel fallback
    if p.port in PORT_INTEL:
        base_risk, reason = PORT_INTEL[p.port]
        p.risk_level  = base_risk
        p.risk_reason = reason
        if p.version_confidence == "NONE" and RISK_ORDER[base_risk] >= RISK_ORDER["HIGH"]:
            p.risk_level  = "MEDIUM"
            p.risk_reason = "[Low confidence] " + reason
        return

    # 4. Generic unknowns
    if p.service in ("http", "http-proxy", "http-alt"):
        p.risk_level  = "MEDIUM"
        p.risk_reason = "HTTP service — web attack surface"
    elif p.port > 49151:
        p.risk_level  = "INFO"
        p.risk_reason = "Ephemeral/dynamic port"
    elif p.service:
        p.risk_level  = "LOW"
        p.risk_reason = f"Service detected: {p.service}"
    else:
        p.risk_level  = "UNKNOWN"
        p.risk_reason = "Unknown service — manual investigation needed"


def detect_attack_paths(host: HostInfo):
    open_set = host.open_port_numbers
    for combo in ATTACK_COMBOS:
        if combo["ports"].issubset(open_set):
            host.attack_paths.append(AttackPath(
                label=combo["label"], risk=combo["risk"],
                hint=combo["hint"], tools=combo["tools"],
                ports=combo["ports"],
            ))


def score_host(host: HostInfo):
    score = 0.0
    highest = "LOW"

    for p in host.open_ports:
        w = RISK_ORDER.get(p.risk_level, 0)
        # CVSS-weighted: actual score gets more weight
        if p.max_cvss:
            score += p.max_cvss * 2.5
        else:
            score += w * w * 1.5
        if p.has_exploit:
            score += 10
        if RISK_ORDER.get(p.risk_level, 0) > RISK_ORDER.get(highest, 0):
            highest = p.risk_level

    # Attack path bonuses
    for ap in host.attack_paths:
        bonus = next((c["risk_bonus"] for c in ATTACK_COMBOS if c["label"] == ap.label), 0)
        score += bonus
        if RISK_ORDER.get(ap.risk, 0) > RISK_ORDER.get(highest, 0):
            highest = ap.risk

    host.risk_score      = round(score, 1)
    host.risk_level      = highest
    host.cve_count       = sum(len(p.cves) for p in host.open_ports)
    host.exploitable_count = sum(1 for p in host.open_ports if p.has_exploit)


# ══════════════════════════════════════════════════════════════════════════════
# MULTI-HOST CORRELATION
# ══════════════════════════════════════════════════════════════════════════════

def correlate_hosts(hosts: list) -> list:
    """Return list of correlation findings as dicts."""
    findings = []

    # Shared vulnerable service versions
    version_map: dict = {}
    for h in hosts:
        for p in h.open_ports:
            if p.version:
                key = f"{p.product} {p.version}".strip()
                if key and key != " ":
                    version_map.setdefault(key, []).append((h.ip, p.port))

    for version_str, hits in version_map.items():
        if len(hits) >= 2:
            findings.append({
                "type": "shared_version",
                "label": f"Shared: {version_str}",
                "hosts": [f"{ip}:{port}" for ip, port in hits],
                "detail": f"{len(hits)} hosts running identical version — patch one, patch all",
            })

    # Shared open ports (potential shared attack surface)
    port_map: dict = {}
    for h in hosts:
        for pn in h.open_port_numbers:
            port_map.setdefault(pn, []).append(h.ip)

    high_risk_ports = {p for p in port_map if p in PORT_INTEL and RISK_ORDER[PORT_INTEL[p][0]] >= RISK_ORDER["HIGH"]}
    for pn in high_risk_ports:
        ips = port_map[pn]
        if len(ips) >= 2:
            findings.append({
                "type": "shared_port",
                "label": f"Port {pn} open on {len(ips)} hosts",
                "hosts": ips,
                "detail": PORT_INTEL[pn][1],
            })

    # Potential pivot chain: host with both internal-style IP and external services
    for h in hosts:
        if h.open_port_numbers & {6379, 27017, 9200} and h.open_port_numbers & {22, 3389}:
            findings.append({
                "type": "pivot_target",
                "label": f"Pivot target: {h.display_name}",
                "hosts": [h.ip],
                "detail": "Exposed DB/cache AND remote access = high-value pivot — compromise DB for lateral move",
            })

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL OUTPUT
# ══════════════════════════════════════════════════════════════════════════════

def c(text: str, level: str) -> str:
    return f"{RISK_COLOUR.get(level, '')}{text}{RESET}"


def risk_tag(level: str, width: int = 10) -> str:
    return c(f"[{level:^{width-2}}]", level)


def bar(filled: int, total: int, width: int = 20, level: str = "HIGH") -> str:
    if total == 0: return "─" * width
    n = round(filled / total * width)
    return c("█" * n, level) + DIM + "░" * (width - n) + RESET


def print_summary(hosts: list, top_n: int, show_all_ports: bool = False):
    sorted_hosts = sorted(
        hosts,
        key=lambda h: (RISK_ORDER.get(h.risk_level, 0), h.risk_score, len(h.open_ports)),
        reverse=True
    )
    show = sorted_hosts[:top_n]

    counts = {lvl: sum(1 for h in hosts if h.risk_level == lvl) for lvl in RISK_ORDER}
    total_cves = sum(h.cve_count for h in hosts)
    total_exploitable = sum(h.exploitable_count for h in hosts)

    W = 76
    print(f"\n{BOLD}{'═'*W}{RESET}")
    print(f"{BOLD}  ▸ NMAP TRIAGE v2  ·  {datetime.now().strftime('%Y-%m-%d %H:%M')}  ·  {len(hosts)} hosts{RESET}")
    print(f"{BOLD}{'═'*W}{RESET}")

    print(f"\n  {c('■ CRITICAL: '+str(counts['CRITICAL']),'CRITICAL')}   "
          f"{c('■ HIGH: '+str(counts['HIGH']),'HIGH')}   "
          f"{c('■ MEDIUM: '+str(counts['MEDIUM']),'MEDIUM')}   "
          f"{c('■ LOW: '+str(counts['LOW']),'LOW')}")
    print(f"  CVEs found: {BOLD}{total_cves}{RESET}   Exploitable: {c(str(total_exploitable),'CRITICAL') if total_exploitable else '0'}")
    print(f"\n  Showing top {len(show)} hosts  (sorted by risk score)\n{'─'*W}\n")

    for rank, host in enumerate(show, 1):
        tag = risk_tag(host.risk_level, 12)
        score_str = f"score={host.risk_score}"
        cve_str   = f"  {c(str(host.cve_count)+' CVEs','HIGH')}" if host.cve_count else ""
        expl_str  = f"  {c('⚡ '+str(host.exploitable_count)+' exploitable','CRITICAL')}" if host.exploitable_count else ""

        print(f"  {BOLD}#{rank:02d}  {host.display_name}{RESET}")
        print(f"       {tag}  {DIM}{score_str}{RESET}{cve_str}{expl_str}")
        if host.os_guess:
            conf = f" ({host.os_confidence}%)" if host.os_confidence else ""
            print(f"       {DIM}OS: {host.os_guess}{conf}{RESET}")
        print(f"       Open ports: {len(host.open_ports)}\n")

        # Ports — sorted by risk then CVSS
        ports_sorted = sorted(
            host.open_ports,
            key=lambda p: (RISK_ORDER.get(p.risk_level, 0), p.max_cvss),
            reverse=True
        )
        for p in ports_sorted:
            tag_p   = c(f"{p.risk_level:<8}", p.risk_level)
            port_s  = f"{p.port}/{p.protocol}"
            svc_s   = p.full_service_str[:42]
            conf_s  = f" {DIM}[no version]{RESET}" if p.version_confidence == "NONE" else ""
            cvss_s  = f"  {c(f'CVSS {p.max_cvss:.1f}', p.risk_level)}" if p.max_cvss else ""
            expl_s  = f"  {c('⚡EXPLOIT','CRITICAL')}" if p.has_exploit else ""

            print(f"       {tag_p}  {port_s:<14}  {svc_s}{conf_s}{cvss_s}{expl_s}")
            print(f"                  {DIM}↳ {p.risk_reason}{RESET}")

            # Show notable script findings (non-vulners, interesting scripts)
            for sf in p.scripts:
                if sf.script_id in ("vulners", "vulscan"):
                    continue  # CVEs handled above
                if sf.risk_level in ("HIGH","CRITICAL","MEDIUM") and sf.output:
                    snippet = sf.output[:120].replace("\n", " ")
                    print(f"                  {CYAN}[{sf.script_id}]{RESET} {DIM}{snippet}{RESET}")

            # Top CVEs
            if p.cves:
                top_cves = sorted(p.cves, key=lambda c: c.cvss, reverse=True)[:3]
                for cve in top_cves:
                    expl = f" {c('⚡','CRITICAL')}" if cve.exploitable else ""
                    print(f"                  {DIM}  CVE: {cve.cve_id}  CVSS {cve.cvss:.1f}{expl}{RESET}")

        # Attack paths
        if host.attack_paths:
            print(f"\n       {BOLD}Attack Paths:{RESET}")
            for ap in host.attack_paths:
                print(f"       {c('  ▸ '+ap.label, ap.risk)}")
                print(f"         {DIM}{ap.hint}{RESET}")
                for tool in ap.tools[:2]:
                    tool_ip = tool.replace("<ip>", host.ip)
                    print(f"         {CYAN}$ {tool_ip}{RESET}")

        print(f"\n{'─'*W}\n")


def print_correlation(findings: list):
    if not findings:
        return
    W = 76
    print(f"\n{BOLD}  ▸ CROSS-HOST CORRELATION{RESET}")
    print(f"{'─'*W}")
    for f in findings:
        icon = {"shared_version": "≡", "shared_port": "⊕", "pivot_target": "⟳"}.get(f["type"], "•")
        print(f"  {CYAN}{icon}{RESET}  {BOLD}{f['label']}{RESET}")
        print(f"     {DIM}{f['detail']}{RESET}")
        hosts_str = ", ".join(f["hosts"][:6])
        if len(f["hosts"]) > 6:
            hosts_str += f" +{len(f['hosts'])-6} more"
        print(f"     Hosts: {hosts_str}")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# JSON EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def export_json(hosts: list, correlations: list, output_path: str):
    def host_to_dict(h: HostInfo) -> dict:
        return {
            "ip": h.ip, "hostname": h.hostname, "os": h.os_guess,
            "os_confidence": h.os_confidence, "mac": h.mac,
            "risk_level": h.risk_level, "risk_score": h.risk_score,
            "cve_count": h.cve_count, "exploitable_count": h.exploitable_count,
            "open_port_count": len(h.open_ports),
            "ports": [port_to_dict(p) for p in h.open_ports],
            "attack_paths": [
                {"label": ap.label, "risk": ap.risk, "hint": ap.hint, "tools": ap.tools}
                for ap in h.attack_paths
            ],
        }

    def port_to_dict(p: PortInfo) -> dict:
        return {
            "port": p.port, "protocol": p.protocol,
            "service": p.full_service_str,
            "risk_level": p.risk_level, "risk_reason": p.risk_reason,
            "max_cvss": p.max_cvss, "has_exploit": p.has_exploit,
            "version_confidence": p.version_confidence,
            "cves": [{"id": c.cve_id, "cvss": c.cvss, "exploitable": c.exploitable} for c in p.cves],
            "scripts": [{"id": s.script_id, "risk": s.risk_level, "output": s.output[:200]} for s in p.scripts],
        }

    data = {
        "generated": datetime.now().isoformat(),
        "summary": {
            "total_hosts": len(hosts),
            "critical": sum(1 for h in hosts if h.risk_level == "CRITICAL"),
            "high":     sum(1 for h in hosts if h.risk_level == "HIGH"),
            "medium":   sum(1 for h in hosts if h.risk_level == "MEDIUM"),
            "low":      sum(1 for h in hosts if h.risk_level in ("LOW","INFO")),
            "total_cves": sum(h.cve_count for h in hosts),
            "exploitable_findings": sum(h.exploitable_count for h in hosts),
        },
        "hosts": [host_to_dict(h) for h in sorted(hosts, key=lambda h: h.risk_score, reverse=True)],
        "correlations": correlations,
    }
    Path(output_path).write_text(json.dumps(data, indent=2))
    print(f"  JSON exported → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ══════════════════════════════════════════════════════════════════════════════

RISK_CSS = {
    "CRITICAL": "#e040fb",
    "HIGH":     "#ff4d4d",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#44cc88",
    "INFO":     "#40c4ff",
    "UNKNOWN":  "#666",
}

def generate_html(hosts: list, correlations: list, output_path: str, top_n: int):
    sorted_hosts = sorted(hosts, key=lambda h: h.risk_score, reverse=True)[:top_n]

    counts = {lvl: sum(1 for h in hosts if h.risk_level == lvl) for lvl in RISK_ORDER}
    total_cves = sum(h.cve_count for h in hosts)
    total_exploitable = sum(h.exploitable_count for h in hosts)

    def badge(level, text=None):
        col = RISK_CSS.get(level, "#666")
        t   = text or level
        return f'<span class="badge" style="background:{col};color:{"#fff" if level in ("CRITICAL","UNKNOWN","INFO") else "#111"}">{t}</span>'

    def cvss_bar(cvss):
        if not cvss: return ""
        pct = min(cvss / 10 * 100, 100)
        col = RISK_CSS.get(cvss_to_risk(cvss), "#666")
        return f'<div class="cvss-bar"><div class="cvss-fill" style="width:{pct:.0f}%;background:{col}"></div><span>{cvss:.1f}</span></div>'

    host_cards = ""
    for rank, host in enumerate(sorted_hosts, 1):
        # Ports table
        port_rows = ""
        for p in sorted(host.open_ports, key=lambda x: (RISK_ORDER.get(x.risk_level,0), x.max_cvss), reverse=True):
            cve_pills = " ".join(
                f'<span class="cve-pill" title="CVSS {c.cvss}">{c.cve_id}{"⚡" if c.exploitable else ""}</span>'
                for c in sorted(p.cves, key=lambda c: c.cvss, reverse=True)[:4]
            )
            scripts_html = ""
            for sf in p.scripts:
                if sf.script_id in ("vulners","vulscan"): continue
                if sf.risk_level in ("HIGH","CRITICAL","MEDIUM"):
                    scripts_html += f'<div class="script-out"><span class="script-id">{sf.script_id}</span> {sf.output[:150]}</div>'

            col = RISK_CSS.get(p.risk_level, "#666")
            conf_warn = ' <span class="conf-warn" title="No version detected — confidence low">?</span>' if p.version_confidence == "NONE" else ""
            port_rows += f"""
            <tr>
              <td>{badge(p.risk_level)}</td>
              <td class="mono">{p.port}/{p.protocol}</td>
              <td class="mono">{p.full_service_str[:50]}{conf_warn}</td>
              <td>{cvss_bar(p.max_cvss)}</td>
              <td class="reason">{p.risk_reason}</td>
              <td>{cve_pills}</td>
            </tr>
            {"<tr><td colspan='6' class='script-row'>"+scripts_html+"</td></tr>" if scripts_html else ""}"""

        # Attack paths
        ap_html = ""
        for ap in host.attack_paths:
            col = RISK_CSS.get(ap.risk, "#666")
            tools_html = "".join(f'<div class="tool-cmd">$ {t.replace("<ip>", host.ip)}</div>' for t in ap.tools[:3])
            ap_html += f"""
            <div class="attack-path" style="border-left:3px solid {col}">
              <div class="ap-label">{badge(ap.risk)} {ap.label}</div>
              <div class="ap-hint">{ap.hint}</div>
              {tools_html}
            </div>"""

        cve_badge  = f'<span class="stat-pill">{host.cve_count} CVEs</span>' if host.cve_count else ""
        expl_badge = f'<span class="stat-pill expl">⚡ {host.exploitable_count} exploitable</span>' if host.exploitable_count else ""
        os_html    = f'<div class="os-row">OS: {host.os_guess}{(" ("+str(host.os_confidence)+"%)" if host.os_confidence else "")}</div>' if host.os_guess else ""

        host_cards += f"""
      <div class="host-card">
        <div class="host-header" style="border-left:4px solid {RISK_CSS.get(host.risk_level,'#666')}">
          <span class="rank">#{rank:02d}</span>
          <span class="host-ip">{host.display_name}</span>
          {badge(host.risk_level)}
          <span class="score">score {host.risk_score}</span>
          <span class="port-count">{len(host.open_ports)} ports</span>
          {cve_badge}{expl_badge}
        </div>
        {os_html}
        <table class="port-table">
          <thead><tr><th>Risk</th><th>Port</th><th>Service</th><th>CVSS</th><th>Reason</th><th>CVEs</th></tr></thead>
          <tbody>{port_rows}</tbody>
        </table>
        {"<div class='ap-section'><div class='ap-title'>Attack Paths</div>"+ap_html+"</div>" if ap_html else ""}
      </div>"""

    # Correlation section
    corr_html = ""
    if correlations:
        rows = ""
        for f in correlations:
            icon = {"shared_version": "≡", "shared_port": "⊕", "pivot_target": "⟳"}.get(f["type"], "•")
            hosts_str = ", ".join(f["hosts"][:5])
            if len(f["hosts"]) > 5: hosts_str += f" +{len(f['hosts'])-5} more"
            rows += f'<tr><td class="corr-icon">{icon}</td><td><strong>{f["label"]}</strong><br><span class="reason">{f["detail"]}</span></td><td class="mono" style="font-size:0.75rem">{hosts_str}</td></tr>'
        corr_html = f"""
      <div class="section-title">Cross-Host Correlation</div>
      <table class="corr-table"><tbody>{rows}</tbody></table>"""

    scan_profile = """
      <div class="scan-tip">
        <strong>💡 Recommended scan for maximum coverage:</strong><br>
        <code>nmap -p- -sV -sC --script vuln,vulners -oA scan &lt;target&gt;</code><br>
        <span>-p- (all ports) · -sV (version detection) · --script vuln,vulners (CVE data) · -oA (all formats)</span>
      </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>nmap_triage v2 — Vulnerability Report</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#080b10;color:#b8c4d8;font-family:'Space Grotesk',sans-serif;font-size:14px;padding:2rem;line-height:1.5}}
h1{{font-family:'JetBrains Mono',monospace;font-size:1.5rem;color:#e8ecf5;letter-spacing:-1px}}
.subtitle{{color:#4a5878;font-family:'JetBrains Mono',monospace;font-size:0.78rem;margin-bottom:2rem}}
.mono{{font-family:'JetBrains Mono',monospace}}

/* Top stats */
.top-stats{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
.stat-box{{background:#0e1320;border:1px solid #1a2035;border-radius:8px;padding:1rem 1.5rem;min-width:110px}}
.stat-val{{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}}
.stat-lbl{{font-size:0.7rem;color:#4a5878;text-transform:uppercase;letter-spacing:0.5px;margin-top:0.3rem}}

/* Badges */
.badge{{padding:2px 8px;border-radius:4px;font-size:0.7rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:0.3px}}
.stat-pill{{background:#1a2035;color:#8899bb;padding:2px 8px;border-radius:4px;font-size:0.72rem;margin-left:4px}}
.stat-pill.expl{{background:#2a1020;color:#ff4d4d}}
.conf-warn{{color:#ffaa00;cursor:help;font-size:0.8rem}}

/* Host cards */
.host-card{{background:#0e1320;border:1px solid #1a2035;border-radius:10px;margin-bottom:1.5rem;overflow:hidden}}
.host-header{{display:flex;align-items:center;gap:0.8rem;flex-wrap:wrap;padding:1rem 1.5rem;background:#0a0d16}}
.rank{{font-family:'JetBrains Mono',monospace;color:#3a4a6a;font-size:0.85rem;font-weight:700}}
.host-ip{{font-family:'JetBrains Mono',monospace;font-weight:700;color:#dde4f5;font-size:1rem}}
.score{{font-size:0.72rem;color:#3a4a6a;font-family:'JetBrains Mono',monospace}}
.port-count{{font-size:0.72rem;color:#3a4a6a}}
.os-row{{padding:0.35rem 1.5rem;font-size:0.75rem;color:#3a4a6a;border-bottom:1px solid #1a2035;background:#0a0d16}}

/* Port table */
.port-table{{width:100%;border-collapse:collapse}}
.port-table thead tr{{background:#080b10}}
.port-table th{{text-align:left;padding:0.45rem 1rem;font-size:0.68rem;color:#2a3a5a;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid #1a2035}}
.port-table td{{padding:0.45rem 1rem;border-bottom:1px solid #111825;vertical-align:top}}
.port-table tr:last-child td{{border-bottom:none}}
.port-table tr:hover td{{background:#0d1220}}
.reason{{color:#4a5878;font-size:0.78rem}}
.script-row td{{background:#08100a;padding:0.3rem 1rem 0.5rem 3rem}}
.script-out{{font-size:0.73rem;color:#44aa66;font-family:'JetBrains Mono',monospace;white-space:pre-wrap;word-break:break-all}}
.script-id{{color:#40c4ff;margin-right:0.5rem;font-weight:600}}

/* CVSS bar */
.cvss-bar{{display:flex;align-items:center;gap:0.4rem;min-width:80px}}
.cvss-fill{{height:6px;border-radius:3px;flex-shrink:0}}
.cvss-bar span{{font-size:0.72rem;font-family:'JetBrains Mono',monospace;color:#8899bb;white-space:nowrap}}

/* CVE pills */
.cve-pill{{display:inline-block;background:#1a1025;color:#cc77ff;border:1px solid #2a1a40;border-radius:3px;padding:1px 5px;font-size:0.68rem;font-family:'JetBrains Mono',monospace;margin:1px;cursor:default}}

/* Attack paths */
.ap-section{{padding:0.8rem 1.5rem;background:#0a0d16;border-top:1px solid #1a2035}}
.ap-title{{font-size:0.72rem;text-transform:uppercase;letter-spacing:0.5px;color:#3a4a6a;margin-bottom:0.5rem;font-weight:600}}
.attack-path{{padding:0.6rem 0.8rem;margin-bottom:0.5rem;border-radius:4px;background:#080b10}}
.ap-label{{font-size:0.82rem;font-weight:600;margin-bottom:0.25rem}}
.ap-hint{{font-size:0.77rem;color:#6b7a99;margin-bottom:0.3rem}}
.tool-cmd{{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#40c4ff;padding:2px 0}}

/* Correlation */
.section-title{{font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;color:#3a4a6a;margin:1.5rem 0 0.5rem;font-weight:700}}
.corr-table{{width:100%;border-collapse:collapse;background:#0e1320;border:1px solid #1a2035;border-radius:8px;overflow:hidden}}
.corr-table td{{padding:0.6rem 1rem;border-bottom:1px solid #111825;vertical-align:top}}
.corr-table tr:last-child td{{border-bottom:none}}
.corr-icon{{font-size:1.1rem;color:#40c4ff;width:30px;text-align:center}}

/* Scan tip */
.scan-tip{{background:#0a1008;border:1px solid #1a3020;border-radius:8px;padding:1rem 1.5rem;margin-top:2rem;font-size:0.78rem;color:#4a7060}}
.scan-tip code{{font-family:'JetBrains Mono',monospace;color:#44cc88;display:block;margin:0.4rem 0}}
.scan-tip strong{{color:#44cc88}}
</style>
</head>
<body>
<h1>◈ nmap_triage v2</h1>
<div class="subtitle">Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ·  {len(hosts)} hosts  ·  top {len(sorted_hosts)} shown</div>

<div class="top-stats">
  <div class="stat-box"><div class="stat-val" style="color:{RISK_CSS['CRITICAL']}">{counts['CRITICAL']}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat-box"><div class="stat-val" style="color:{RISK_CSS['HIGH']}">{counts['HIGH']}</div><div class="stat-lbl">High</div></div>
  <div class="stat-box"><div class="stat-val" style="color:{RISK_CSS['MEDIUM']}">{counts['MEDIUM']}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat-box"><div class="stat-val" style="color:{RISK_CSS['LOW']}">{counts['LOW']}</div><div class="stat-lbl">Low</div></div>
  <div class="stat-box"><div class="stat-val" style="color:#cc77ff">{total_cves}</div><div class="stat-lbl">Total CVEs</div></div>
  <div class="stat-box"><div class="stat-val" style="color:{RISK_CSS['CRITICAL']}">{total_exploitable}</div><div class="stat-lbl">Exploitable</div></div>
</div>

{host_cards}
{corr_html}
{scan_profile}
</body>
</html>"""

    Path(output_path).write_text(html)
    print(f"  HTML report → {output_path}")


# ══════════════════════════════════════════════════════════════════════════════
# DEMO XML (rich — includes NSE script output with CVEs)
# ══════════════════════════════════════════════════════════════════════════════

DEMO_XML = """<?xml version="1.0"?>
<nmaprun>

  <!-- Windows server: SMB + RDP + Apache vuln + SSH -->
  <host><status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac"/>
    <hostnames><hostname name="fileserver.corp" type="PTR"/></hostnames>
    <os><osmatch name="Windows Server 2019" accuracy="94"/></os>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Windows SMB" conf="10"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) CVSS: 9.3 CVE-2017-0143"/>
        <script id="smb-security-mode" output="account_used: guest; authentication_level: user; challenge_response: supported; message_signing: disabled"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" version="10.0" conf="10"/>
        <script id="rdp-vuln-ms12-020" output="MS12-020 Remote Desktop Protocol Denial of Service Vulnerability CVSS: 9.3 CVE-2012-0152"/>
      </port>
      <port protocol="tcp" portid="135"><state state="open"/><service name="msrpc" product="Microsoft Windows RPC" conf="10"/></port>
      <port protocol="tcp" portid="139"><state state="open"/><service name="netbios-ssn" product="Microsoft Windows netbios-ssn" conf="10"/></port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49" conf="10"/>
        <script id="vulners" output="cpe:/a:apache:http_server:2.4.49:
        CVE-2021-41773  9.8  https://vulners.com/cve/CVE-2021-41773
        CVE-2021-42013  9.8  https://vulners.com/cve/CVE-2021-42013">
          <table key="CVE-2021-41773"><elem key="id">CVE-2021-41773</elem><elem key="cvss">9.8</elem><elem key="type">webapps exploit</elem></table>
          <table key="CVE-2021-42013"><elem key="id">CVE-2021-42013</elem><elem key="cvss">9.8</elem><elem key="type">webapps exploit</elem></table>
        </script>
        <script id="http-headers" output="Server: Apache/2.4.49 (Unix)&#xa;X-Powered-By: PHP/7.0.33&#xa;X-Frame-Options: MISSING"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4" conf="10"/>
        <script id="vulners" output="cpe:/a:openbsd:openssh:7.4">
          <table key="CVE-2018-15473"><elem key="id">CVE-2018-15473</elem><elem key="cvss">5.3</elem><elem key="type">other</elem></table>
        </script>
      </port>
    </ports>
    <hostscript>
      <script id="smb-vuln-ms17-010" output="VULNERABLE: ms17-010 EternalBlue CVE-2017-0143 CVSS:9.3"/>
    </hostscript>
  </host>

  <!-- Linux data node: Redis + MongoDB + ES + Docker -->
  <host><status state="up"/>
    <address addr="192.168.1.25" addrtype="ipv4"/>
    <os><osmatch name="Linux 4.15" accuracy="87"/></os>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="3.0.7" conf="10"/>
        <script id="redis-info" output="redis_version:3.0.7&#xa;authenticated: no&#xa;config_file: /etc/redis/redis.conf"/>
      </port>
      <port protocol="tcp" portid="27017">
        <state state="open"/>
        <service name="mongod" product="MongoDB" version="2.6.12" conf="10"/>
        <script id="mongodb-info" output="MongoDB server info - No auth required&#xa;databases: users, payments, logs"/>
      </port>
      <port protocol="tcp" portid="9200">
        <state state="open"/>
        <service name="http" product="Elasticsearch REST API" version="1.7.6" conf="10"/>
        <script id="vulners" output="cpe:/a:elastic:elasticsearch:1.7.6">
          <table key="CVE-2021-22144"><elem key="id">CVE-2021-22144</elem><elem key="cvss">6.5</elem><elem key="type">other</elem></table>
        </script>
      </port>
      <port protocol="tcp" portid="2375">
        <state state="open"/>
        <service name="docker" product="Docker" version="19.03.6" conf="10"/>
        <script id="docker-version" output="API Version: 1.40&#xa;Auth: none&#xa;Containers: 12 Running"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2" conf="10"/>
      </port>
    </ports>
  </host>

  <!-- Legacy box: vsftpd backdoor + Telnet + rexec -->
  <host><status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="legacy-ftp.corp" type="PTR"/></hostnames>
    <os><osmatch name="Linux 2.6.x" accuracy="91"/></os>
    <ports>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="2.3.4" conf="10"/>
        <script id="ftp-vsftpd-backdoor" output="BACKDOOR FOUND - State: VULNERABLE&#xa;Payload sent: 0x3a0x29&#xa;Shell: Connected"/>
        <script id="vulners" output="cpe:/a:vsftpd_project:vsftpd:2.3.4">
          <table key="CVE-2011-2523"><elem key="id">CVE-2011-2523</elem><elem key="cvss">10.0</elem><elem key="type">remote exploit</elem></table>
        </script>
      </port>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" conf="5"/></port>
      <port protocol="tcp" portid="512"><state state="open"/><service name="exec" conf="5"/></port>
      <port protocol="tcp" portid="513"><state state="open"/><service name="login" conf="5"/></port>
      <port protocol="tcp" portid="1099">
        <state state="open"/>
        <service name="java-rmi" product="GNU Classpath grmiregistry" conf="8"/>
        <script id="rmi-vuln-classloader" output="VULNERABLE: RMI registry default configuration remote code execution"/>
      </port>
    </ports>
  </host>

  <!-- Relatively clean web server -->
  <host><status state="up"/>
    <address addr="10.0.0.12" addrtype="ipv4"/>
    <hostnames><hostname name="web01.corp" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.4" accuracy="78"/></os>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0" conf="10"/>
        <script id="ssl-cert" output="Subject: CN=web01.corp&#xa;Issuer: Let's Encrypt&#xa;Validity: 2025-01-01 - 2025-04-01 EXPIRED"/>
        <script id="ssl-enum-ciphers" output="TLSv1.0: supported (WEAK)&#xa;TLSv1.2: supported&#xa;TLSv1.3: supported"/>
      </port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24.0" conf="10"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9" conf="10"/></port>
      <port protocol="tcp" portid="53"><state state="open"/><service name="domain" product="ISC BIND" version="9.16.1" conf="10"/></port>
    </ports>
  </host>

  <!-- Kubernetes node -->
  <host><status state="up"/>
    <address addr="10.10.0.50" addrtype="ipv4"/>
    <hostnames><hostname name="k8s-node-01" type="PTR"/></hostnames>
    <os><osmatch name="Linux 5.15" accuracy="82"/></os>
    <ports>
      <port protocol="tcp" portid="10250">
        <state state="open"/>
        <service name="ssl/http" product="Golang net/http" conf="10"/>
        <script id="kubelet-pods" output="HTTP/1.1 200 OK&#xa;Anonymous auth: enabled&#xa;Pods: 18 running"/>
      </port>
      <port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" version="6.2.6" conf="10"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9" conf="10"/></port>
    </ports>
  </host>

</nmaprun>"""


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="nmap_triage v2 — elite nmap XML parser and vulnerability ranker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Recommended scan:
  nmap -p- -sV -sC --script vuln,vulners -oX scan.xml <target>

Examples:
  python nmap_triage.py scan.xml
  python nmap_triage.py scan.xml --top 15 --html report.html --json out.json
  python nmap_triage.py scan.xml --only-high
  python nmap_triage.py scan.xml --min-cvss 7.0
  python nmap_triage.py scan.xml --only-exploitable
  python nmap_triage.py --demo --html demo.html
        """
    )
    parser.add_argument("input",              nargs="?",            help="Nmap XML file (-oX output)")
    parser.add_argument("--top",              type=int, default=20, metavar="N",   help="Show top N hosts (default: 20)")
    parser.add_argument("--html",             metavar="FILE",                      help="Write HTML report")
    parser.add_argument("--json",             metavar="FILE",                      help="Write JSON export")
    parser.add_argument("--only-high",        action="store_true",                 help="Show only HIGH/CRITICAL hosts")
    parser.add_argument("--only-exploitable", action="store_true",                 help="Show only hosts with exploitable CVEs")
    parser.add_argument("--min-cvss",         type=float, default=0, metavar="N",  help="Filter to hosts with CVSS >= N")
    parser.add_argument("--demo",             action="store_true",                 help="Run with built-in rich demo data")
    args = parser.parse_args()

    # Load data
    if args.demo:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            f.write(DEMO_XML)
            tmp = f.name
        hosts = parse_nmap_xml(tmp)
        os.unlink(tmp)
        print(f"\n  {DIM}[demo mode]{RESET}")
    elif args.input:
        if not Path(args.input).exists():
            print(f"Error: file not found — {args.input}", file=sys.stderr)
            sys.exit(1)
        hosts = parse_nmap_xml(args.input)
    else:
        parser.print_help()
        sys.exit(0)

    if not hosts:
        print("No live hosts found in scan.")
        sys.exit(0)

    # Apply filters
    filtered = hosts
    if args.only_high:
        filtered = [h for h in hosts if h.risk_level in ("HIGH","CRITICAL")]
    if args.only_exploitable:
        filtered = [h for h in filtered if h.exploitable_count > 0]
    if args.min_cvss:
        filtered = [h for h in filtered if any(p.max_cvss >= args.min_cvss for p in h.open_ports)]

    correlations = correlate_hosts(hosts)  # always correlate full set

    print_summary(filtered, args.top)
    print_correlation(correlations)

    if args.html:
        generate_html(filtered, correlations, args.html, args.top)
    if args.json:
        export_json(filtered, correlations, args.json)

    # Scan profile reminder
    print(f"\n  {DIM}Tip: for full CVE data run:{RESET}")
    print(f"  {CYAN}nmap -p- -sV -sC --script vuln,vulners -oX scan.xml <target>{RESET}\n")


if __name__ == "__main__":
    main()
