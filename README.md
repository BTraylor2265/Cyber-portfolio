# Blaine Traylor — Technical Portfolio

I work in enterprise IT operations at Crown Castle managing compliance workflows, access governance, and system documentation in a regulated telecom environment. I'm currently pursuing an M.S. in Information Assurance and Cybersecurity at Sam Houston State while building toward security-focused technical work on the side.

These projects came out of that process — things I built to understand how detection actually works, not just read about it.

---

## Network Traffic Analyzer

**Stack:** Python, Wireshark, TCP/IP

I wanted to understand what suspicious network traffic actually looks like in packet data — not conceptually, but at the byte level. So I built a parser that takes a Wireshark CSV export and runs it through six detection checks automatically.

**What it catches:**
- C2 beaconing — repeated connections from one internal host to one external IP (flagged at 15+ packets)
- Plaintext protocol exposure — FTP, Telnet, HTTP traffic where credentials can be intercepted
- Suspicious destination ports — 4444 (Metasploit handler), 6667 (IRC/botnet), 31337, 8080
- RST storms — possible port scan or DoS behavior from a single source
- Top talkers — hosts generating disproportionate outbound packet volume
- Low encryption ratio — overall percentage of encrypted vs plaintext traffic

Findings write to a structured text report aligned to NIST SP 800-115 testing methodology.

**Run the demo (no Wireshark needed):**
```bash
python network_traffic_analyzer.py --demo
```
The demo generates 500 synthetic packets with injected threats so you can see the full output without a real capture file.

**One thing I ran into:** Windows throws a UnicodeEncodeError when writing emoji characters to a text file using the default cp1252 encoding. Fixed by specifying `encoding='utf-8'` on the file write — simple fix but took a minute to track down.

**Files:**
- `network_traffic_analyzer.py` — main script
- `sample_output.txt` — example report from a demo run

---

## Windows Security Log Analyzer

**Stack:** PowerShell, Windows Event Viewer, MITRE ATT&CK

This came from the Windows Security Log Analysis lab work I was doing — I wanted to automate the correlation part instead of manually reviewing Event Viewer every time. The script queries the Security event log and ties what it finds to MITRE ATT&CK techniques so the output is actually actionable, not just a raw list of events.

**Event IDs it covers:**

| Event ID | What it means | MITRE mapping |
|----------|--------------|---------------|
| 4624 | Successful logon | T1078 Valid Accounts |
| 4625 | Failed logon | T1110 Brute Force |
| 4672 | Special privileges assigned | T1078.002 |
| 4720 | New account created | T1136 Create Account |
| 4740 | Account locked out | T1531 |

Output is an incident-style report with HIGH/MEDIUM severity ratings and a findings summary.

**Run it (requires Administrator):**
```powershell
.\SecurityLogAnalyzer.ps1 -Hours 24
.\SecurityLogAnalyzer.ps1 -Hours 48 -Report .\my_report.txt
```

**Note:** You need to run PowerShell as Administrator to read the Security event log. The script will warn you if it can't access the log rather than failing silently.

**Files:**
- `SecurityLogAnalyzer.ps1` — main script

---

## Skills this work covers

Python scripting for data parsing and threat detection, PowerShell for Windows log automation, network protocol fundamentals (TCP/IP, DNS, TLS, FTP), MITRE ATT&CK framework mapping, NIST SP 800-115 testing methodology, incident documentation and severity classification.

---

## Background

Currently working toward Security+ and Azure fundamentals alongside the graduate program. Crown Castle background covers ServiceNow workflow management, SQL data validation, access governance (RBAC/IAM), and compliance documentation in a publicly traded telecom REIT.

Open to connecting: blaine_traylor@yahoo.com | [LinkedIn](https://linkedin.com/in/Blaine-t)
