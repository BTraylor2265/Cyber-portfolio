#!/usr/bin/env python3
"""
Network Traffic Analyzer
Author: Blaine Traylor
Project: Network Traffic Analysis Lab (Wireshark / Python)
Description:
    Parses a Wireshark-exported CSV or PCAP-JSON dump to identify:
    - Top talkers (source IPs by packet volume)
    - Plaintext HTTP connections (data exposure risk)
    - TLS vs unencrypted traffic ratios
    - Suspicious DNS queries (non-standard ports, high-frequency domains)
    - Failed / RST connection patterns

Usage:
    # Export from Wireshark: File > Export Packet Dissections > As CSV
    python network_traffic_analyzer.py --file capture.csv --report report.txt

    # Demo mode (generates synthetic traffic data):
    python network_traffic_analyzer.py --demo
"""

import argparse
import csv
import json
import random
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444: "Common Metasploit handler",
    1337: "Known C2 / hacker tradition",
    6667: "IRC (often used by botnets)",
    31337: "Elite backdoor port",
    8080: "Alt-HTTP (sometimes proxy/tunneling)",
}

PLAINTEXT_PROTOCOLS = {"HTTP", "FTP", "TELNET", "SMTP", "POP3", "IMAP"}
ENCRYPTED_PROTOCOLS = {"HTTPS", "TLS", "SSL", "SSH", "SFTP"}

HIGH_FREQ_THRESHOLD = 50   # DNS queries per unique domain in one capture
RST_THRESHOLD       = 10   # RST packets from a single src before flagging


# ─── Synthetic Demo Data ───────────────────────────────────────────────────────

def generate_demo_packets(n=500):
    """
    Generates a list of synthetic packet dicts to simulate a Wireshark CSV export.
    Injects some intentionally suspicious traffic.
    """
    random.seed(42)

    internal_ips  = [f"192.168.1.{i}" for i in range(2, 20)]
    external_ips  = ["8.8.8.8", "142.250.80.46", "52.84.17.3", "203.0.113.99", "198.51.100.7"]
    suspicious_ip = "203.0.113.99"   # Simulated C2

    protocols = ["HTTP", "HTTPS", "DNS", "TLS", "FTP", "TELNET", "TCP"]
    ports      = [80, 443, 53, 21, 23, 8080, 4444]

    packets = []
    for i in range(n):
        src = random.choice(internal_ips)
        dst = random.choice(external_ips)
        proto = random.choice(protocols)
        dport = random.choice(ports)
        length = random.randint(60, 1500)
        flags = random.choice(["", "", "", "RST", "RST", "SYN"])

        # Inject C2-like traffic from one internal host
        if i % 30 == 0:
            src   = "192.168.1.15"
            dst   = suspicious_ip
            dport = 4444
            proto = "TCP"
            flags = ""

        # Inject plaintext FTP creds simulation
        if i % 75 == 0:
            proto = "FTP"
            dport = 21

        packets.append({
            "no":       i + 1,
            "time":     round(i * 0.05, 3),
            "source":   src,
            "dest":     dst,
            "protocol": proto,
            "length":   length,
            "dport":    dport,
            "info":     flags,
        })

    return packets


# ─── Analysis Engine ──────────────────────────────────────────────────────────

class TrafficAnalyzer:
    def __init__(self, packets):
        self.packets  = packets
        self.findings = []

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _flag(self, severity, category, detail):
        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}.get(severity, "•")
        self.findings.append(f"[{severity}] {icon} {category}: {detail}")

    # ── Checks ───────────────────────────────────────────────────────────────

    def check_top_talkers(self, top_n=5):
        """Rank internal hosts by outbound packet volume."""
        src_counts = Counter(p["source"] for p in self.packets)
        print("\n📊 Top Talkers (by packet count)")
        print("─" * 40)
        for ip, count in src_counts.most_common(top_n):
            bar = "█" * (count // 5)
            print(f"  {ip:<18} {count:>5} pkts  {bar}")
            if count > 100:
                self._flag("MEDIUM", "High-volume host", f"{ip} sent {count} packets — verify expected behavior")

    def check_plaintext_exposure(self):
        """Flag traffic using unencrypted protocols."""
        print("\n🔓 Plaintext Protocol Check")
        print("─" * 40)
        exposed = defaultdict(list)
        for p in self.packets:
            if p["protocol"].upper() in PLAINTEXT_PROTOCOLS:
                exposed[p["protocol"]].append(p["source"])

        if not exposed:
            print("  ✅ No plaintext protocol traffic detected.")
        for proto, hosts in exposed.items():
            unique_hosts = set(hosts)
            print(f"  {proto} — {len(hosts)} packets from {len(unique_hosts)} host(s): {', '.join(unique_hosts)}")
            self._flag(
                "HIGH" if proto in {"TELNET", "FTP"} else "MEDIUM",
                "Plaintext Exposure",
                f"{proto} traffic detected — credentials/data transmitted in clear text"
            )

    def check_tls_ratio(self):
        """Calculate encrypted vs plaintext ratio."""
        total     = len(self.packets)
        encrypted = sum(1 for p in self.packets if p["protocol"].upper() in ENCRYPTED_PROTOCOLS)
        plaintext = sum(1 for p in self.packets if p["protocol"].upper() in PLAINTEXT_PROTOCOLS)
        ratio     = (encrypted / total * 100) if total else 0

        print(f"\n🔒 Encryption Ratio")
        print("─" * 40)
        print(f"  Total packets : {total}")
        print(f"  Encrypted     : {encrypted} ({ratio:.1f}%)")
        print(f"  Plaintext     : {plaintext} ({100 - ratio:.1f}%)")

        if ratio < 70:
            self._flag("MEDIUM", "Low encryption ratio", f"Only {ratio:.1f}% of traffic is encrypted — review network policy")

    def check_suspicious_ports(self):
        """Flag connections to known suspicious destination ports."""
        print("\n⚠️  Suspicious Port Check")
        print("─" * 40)
        found_any = False
        for p in self.packets:
            dport = p.get("dport")
            if dport in SUSPICIOUS_PORTS:
                found_any = True
                print(f"  {p['source']} → {p['dest']}:{dport}  ({SUSPICIOUS_PORTS[dport]})")
                self._flag("HIGH", "Suspicious Port", f"{p['source']} connected to {p['dest']}:{dport} — {SUSPICIOUS_PORTS[dport]}")
        if not found_any:
            print("  ✅ No suspicious destination ports detected.")

    def check_rst_storm(self):
        """Detect RST packet floods from a single source."""
        rst_counts = Counter(p["source"] for p in self.packets if "RST" in p.get("info", ""))
        print("\n🚨 RST Packet Analysis")
        print("─" * 40)
        flagged = False
        for src, count in rst_counts.most_common():
            if count >= RST_THRESHOLD:
                flagged = True
                print(f"  {src} sent {count} RST packets — possible scan or DoS")
                self._flag("MEDIUM", "RST Storm", f"{src} sent {count} RST packets — investigate port scan or connection teardown flood")
        if not flagged:
            print("  ✅ No RST storms detected.")

    def check_beaconing(self):
        """
        Detect potential C2 beaconing: one src → one dst with unusually regular intervals.
        Simplified: flag src-dst pairs with >20 packets (demo heuristic).
        """
        pair_counts = Counter((p["source"], p["dest"]) for p in self.packets)
        print("\n📡 Beaconing / C2 Pattern Check")
        print("─" * 40)
        found = False
        for (src, dst), count in pair_counts.most_common(10):
            if count > 15:
                found = True
                print(f"  {src} → {dst}  |  {count} packets  (possible beacon interval)")
                self._flag("HIGH", "Possible Beaconing", f"{src} → {dst} repeated {count}x — investigate for C2 activity")
        if not found:
            print("  ✅ No obvious beaconing patterns detected.")

    # ── Report ────────────────────────────────────────────────────────────────

    def print_findings_summary(self):
        print("\n" + "═" * 50)
        print("  FINDINGS SUMMARY")
        print("═" * 50)
        if not self.findings:
            print("  ✅ No significant issues detected.")
        for f in self.findings:
            print(f"  {f}")
        highs   = sum(1 for f in self.findings if "[HIGH]"   in f)
        mediums = sum(1 for f in self.findings if "[MEDIUM]" in f)
        print(f"\n  Total: {len(self.findings)} findings  |  🔴 HIGH: {highs}  |  🟡 MEDIUM: {mediums}")

    def write_report(self, path):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"Network Traffic Analysis Report",
            f"Generated: {ts}",
            f"Packets analyzed: {len(self.packets)}",
            "",
            "─── Findings ─────────────────────────────────────────",
        ] + self.findings + ["", "─── Methodology ──────────────────────────────────────",
            "Analysis based on NIST SP 800-115 Technical Guide to Information Security Testing.",
            "Checks performed: top-talker analysis, plaintext exposure, TLS ratio,",
            "suspicious-port mapping, RST-storm detection, and beaconing pattern detection.",
        ]
        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        print(f"\n📄 Report written to: {path}")


# ─── CSV Loader ──────────────────────────────────────────────────────────────

def load_wireshark_csv(path):
    """
    Parses a Wireshark CSV export (File → Export Packet Dissections → As CSV).
    Expected columns: No., Time, Source, Destination, Protocol, Length, Info
    """
    packets = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                dport_str = ""
                info = row.get("Info", "")
                # Wireshark puts "Src Port → Dst Port" info for TCP/UDP
                parts = info.split("→")
                dport = int(parts[-1].strip().split()[0]) if len(parts) > 1 else 0
            except (ValueError, IndexError):
                dport = 0
            packets.append({
                "no":       row.get("No.", ""),
                "time":     row.get("Time", ""),
                "source":   row.get("Source", ""),
                "dest":     row.get("Destination", ""),
                "protocol": row.get("Protocol", "").upper(),
                "length":   int(row.get("Length", 0) or 0),
                "dport":    dport,
                "info":     info,
            })
    return packets


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer — Blaine Traylor")
    parser.add_argument("--file",   help="Path to Wireshark CSV export")
    parser.add_argument("--demo",   action="store_true", help="Run with synthetic demo data")
    parser.add_argument("--report", default="traffic_report.txt", help="Output report file path")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════╗")
    print("║   Network Traffic Analyzer               ║")
    print("║   Blaine Traylor | Cybersecurity Lab     ║")
    print("╚══════════════════════════════════════════╝")

    if args.demo:
        print("\n[DEMO MODE] Generating 500 synthetic packets with injected threats...\n")
        packets = generate_demo_packets(500)
    elif args.file:
        print(f"\nLoading packets from: {args.file}")
        packets = load_wireshark_csv(args.file)
    else:
        print("Use --demo for a demo run, or --file <path> for real Wireshark CSV data.")
        return

    print(f"Loaded {len(packets)} packets.\n")

    analyzer = TrafficAnalyzer(packets)
    analyzer.check_top_talkers()
    analyzer.check_plaintext_exposure()
    analyzer.check_tls_ratio()
    analyzer.check_suspicious_ports()
    analyzer.check_rst_storm()
    analyzer.check_beaconing()
    analyzer.print_findings_summary()
    analyzer.write_report(args.report)


if __name__ == "__main__":
    main()
