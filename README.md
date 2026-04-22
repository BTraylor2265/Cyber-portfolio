# Technical Projects — Blaine Traylor

M.S. Information Assurance & Cybersecurity student at Sam Houston State University.
Background in enterprise access governance, compliance, and security operations at Crown Castle.

---

## Projects

### 🔍 Network Traffic Analyzer
**Tools:** Python, Wireshark, TCP/IP, PCAP analysis

Parses Wireshark packet captures to detect:
- C2 beaconing patterns
- Plaintext protocol exposure (FTP, Telnet, HTTP)
- Suspicious destination ports (4444, 6667, etc.)
- RST storms and top-talker anomalies

Findings are mapped to NIST SP 800-115 methodology and written to a structured report.

**Run it:**
```bash
python network_traffic_analyzer.py --demo
```

---

### 🪟 Windows Security Log Analyzer
**Tools:** PowerShell, Windows Event Viewer, MITRE ATT&CK

Queries Windows Security event logs to surface:
- Brute-force attempts (Event 4625) → MITRE T1110
- Privilege escalation (Event 4672) → MITRE T1078.002
- New account creation (Event 4720) → MITRE T1136
- Account lockouts (Event 4740)

Outputs an incident-style summary report with severity ratings.

**Run it (as Administrator):**
```powershell
.\SecurityLogAnalyzer.ps1 -Hours 24
```

---

## Skills Demonstrated
- Network traffic analysis & packet inspection
- Windows event log correlation
- MITRE ATT&CK framework mapping
- NIST SP 800-115 testing methodology
- PowerShell scripting for security automation
- Python scripting for threat detection

---

📫 blaine_traylor@yahoo.com | [LinkedIn](https://linkedin.com/in/Blaine-t)
```
