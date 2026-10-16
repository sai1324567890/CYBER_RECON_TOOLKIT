#!/usr/bin/env python3
import argparse
import concurrent.futures as cf
import html
import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")

# port -> (service, severity, advice)
RISKY_PORTS = {
    21: ("FTP", "MEDIUM", "FTP sends credentials in clear text. Use SFTP/FTPS."),
    23: ("Telnet", "HIGH", "Telnet is unencrypted. Disable it and use SSH."),
    25: ("SMTP", "LOW", "Ensure open relay is disabled and TLS is enforced."),
    69: ("TFTP", "HIGH", "TFTP has no authentication. Disable or restrict by ACL."),
    110: ("POP3", "MEDIUM", "Use POP3S (995) instead of clear-text POP3."),
    135: ("MS-RPC", "MEDIUM", "Block RPC from untrusted networks."),
    139: ("NetBIOS", "MEDIUM", "Disable NetBIOS over TCP/IP where possible."),
    445: ("SMB", "HIGH", "SMB exposure enables worm/ransomware spread. Patch and restrict."),
    1433: ("MSSQL", "MEDIUM", "Do not expose databases directly; use VPN/bastion."),
    3306: ("MySQL", "MEDIUM", "Do not expose databases directly; bind to localhost/VPN."),
    3389: ("RDP", "HIGH", "Expose RDP only via VPN, enforce NLA and MFA."),
    5432: ("PostgreSQL", "MEDIUM", "Restrict listen_addresses and pg_hba.conf."),
    5900: ("VNC", "HIGH", "VNC is weakly protected. Tunnel over SSH/VPN."),
    6379: ("Redis", "HIGH", "Redis without auth is remotely exploitable. Enable requirepass."),
    27017: ("MongoDB", "HIGH", "Enable authentication and bind to private interfaces."),
}
SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def parse_ports(spec):
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"Invalid port(s): {bad}")
    return sorted(ports)


def expand_targets(target, authorized):
    """Resolve a hostname / IP / CIDR into a list of IP strings, enforcing the
    private-network guard unless --authorized is set."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        hosts = [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    except ValueError:
        try:
            hosts = [socket.gethostbyname(target)]
        except socket.gaierror:
            sys.exit(f"Cannot resolve target: {target}")
    if len(hosts) > 1024:
        sys.exit("Refusing to scan more than 1024 hosts in one run.")
    if not authorized:
        for h in hosts:
            ip = ipaddress.ip_address(h)
            if not (ip.is_private or ip.is_loopback):
                sys.exit(f"{h} is a public address. Re-run with --authorized only if you "
                         f"have written permission to test it.")
    return hosts


def make_finding(host, port, service, severity, detail, advice):
    return {"host": host, "port": port, "service": service,
            "severity": severity, "detail": detail, "advice": advice}


def assess_open_port(host, port, service="", version=""):
    name, sev, advice = RISKY_PORTS.get(port, (service or "unknown", "INFO",
                                               "Confirm this service is required."))
    detail = f"Open port {port}/{name}" + (f" ({version})" if version else "")
    return make_finding(host, port, name, sev, detail, advice)


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def nmap_scan(host, ports, vuln=False, timeout=300):
    """Run Nmap and parse its XML output."""
    port_arg = ",".join(map(str, ports))
    cmd = ["nmap", "-Pn", "-sV", "-p", port_arg, "-oX", "-", host]
    if vuln:
        cmd[1:1] = ["--script", "vuln,default"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "nmap failed")
    root = ET.fromstring(proc.stdout)
    findings, open_ports = [], []
    for p in root.iter("port"):
        state = p.find("state")
        if state is None or state.get("state") != "open":
            continue
        port = int(p.get("portid"))
        svc = p.find("service")
        service = svc.get("name", "") if svc is not None else ""
        version = " ".join(filter(None, [svc.get("product", ""), svc.get("version", "")])) if svc is not None else ""
        open_ports.append({"port": port, "service": service, "version": version})
        findings.append(assess_open_port(host, port, service, version))
        for script in p.iter("script"):
            out = (script.get("output") or "").strip()
            if "VULNERABLE" in out.upper():
                findings.append(make_finding(
                    host, port, service, "CRITICAL",
                    f"Nmap script '{script.get('id')}' reports: {out[:300]}",
                    "Patch or mitigate per the referenced CVE advisory."))
    return open_ports, findings


def socket_scan(host, ports, timeout=0.6, workers=200):
    """Pure-Python TCP connect scan (fallback when Nmap is unavailable)."""
    def probe(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = ""
                try:
                    s.settimeout(0.4)
                    banner = s.recv(80).decode(errors="ignore").strip()
                except Exception:
                    pass
                return port, banner
        return None

    open_ports, findings = [], []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(probe, ports):
            if res:
                port, banner = res
                try:
                    svc = socket.getservbyport(port)
                except OSError:
                    svc = "unknown"
                open_ports.append({"port": port, "service": svc, "version": banner[:60]})
                findings.append(assess_open_port(host, port, svc, banner[:60]))
    return open_ports, findings


def run_scan(args):
    ports = parse_ports(args.ports)
    hosts = expand_targets(args.target, args.authorized)
    use_nmap = shutil.which("nmap") is not None and not args.no_nmap
    engine = "nmap" if use_nmap else "python-socket"
    print(f"[*] Scanning {len(hosts)} host(s), {len(ports)} port(s) using engine: {engine}")
    if not use_nmap and args.vuln:
        print("[!] --vuln needs Nmap (https://nmap.org). Continuing with basic port scan.")

    results, findings = {}, []
    for h in hosts:
        try:
            if use_nmap:
                op, fi = nmap_scan(h, ports, args.vuln)
            else:
                op, fi = socket_scan(h, ports)
        except Exception as e:
            print(f"[!] {h}: {e}")
            continue
        if op:
            print(f"[+] {h}: {len(op)} open port(s): {', '.join(str(p['port']) for p in op)}")
        results[h], findings = op, findings + fi
    write_reports("scan", {"engine": engine, "target": args.target, "hosts": results}, findings)


# --------------------------------------------------------------------------
# Traffic analysis (Wireshark-compatible)
# --------------------------------------------------------------------------
class TrafficAnalyzer:
    """Detects port scans, SYN floods, ICMP floods, and ARP spoofing from packets."""

    def __init__(self, scan_ports=15, syn_rate=100, icmp_rate=100, window=10):
        self.scan_ports, self.syn_rate = scan_ports, syn_rate
        self.icmp_rate, self.window = icmp_rate, window
        self.syn_ports = defaultdict(lambda: defaultdict(set))      # src -> bucket -> ports
        self.syn_count = defaultdict(lambda: defaultdict(int))      # src -> bucket -> count
        self.icmp_count = defaultdict(lambda: defaultdict(int))
        self.arp_table = defaultdict(set)                           # ip -> {macs}
        self.total = 0

    def feed(self, pkt):
        from scapy.layers.inet import ICMP, IP, TCP
        from scapy.layers.l2 import ARP
        self.total += 1
        ts = float(pkt.time)
        bucket = int(ts // self.window)
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            self.arp_table[pkt[ARP].psrc].add(pkt[ARP].hwsrc)
        if not pkt.haslayer(IP):
            return
        src = pkt[IP].src
        if pkt.haslayer(TCP) and (int(pkt[TCP].flags) & 0x12) == 0x02:   # SYN, no ACK
            self.syn_ports[src][bucket].add(pkt[TCP].dport)
            self.syn_count[src][bucket] += 1
        elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:                 # echo request
            self.icmp_count[src][bucket] += 1

    def findings(self):
        out = []
        for src, buckets in self.syn_ports.items():
            for b, ports in buckets.items():
                if len(ports) >= self.scan_ports:
                    out.append(make_finding(
                        src, None, "TCP", "HIGH",
                        f"Possible PORT SCAN: {src} probed {len(ports)} distinct ports within {self.window}s",
                        "Block/rate-limit the source and review firewall logs."))
                    break
        for src, buckets in self.syn_count.items():
            peak = max(buckets.values())
            if peak >= self.syn_rate:
                out.append(make_finding(
                    src, None, "TCP", "CRITICAL",
                    f"Possible SYN FLOOD: {peak} SYN packets from {src} within {self.window}s",
                    "Enable SYN cookies and upstream rate limiting."))
        for src, buckets in self.icmp_count.items():
            peak = max(buckets.values())
            if peak >= self.icmp_rate:
                out.append(make_finding(
                    src, None, "ICMP", "MEDIUM",
                    f"Possible ICMP FLOOD/sweep: {peak} echo requests from {src} within {self.window}s",
                    "Rate-limit ICMP at the perimeter."))
        for ip, macs in self.arp_table.items():
            if len(macs) > 1:
                out.append(make_finding(
                    ip, None, "ARP", "CRITICAL",
                    f"Possible ARP SPOOFING: {ip} claimed by multiple MACs {sorted(macs)}",
                    "Enable dynamic ARP inspection / static ARP entries."))
        return out


def run_analyze(args):
    from scapy.utils import PcapReader
    path = Path(args.pcap)
    if not path.exists():
        sys.exit(f"File not found: {path}")
    an = TrafficAnalyzer(args.scan_ports, args.syn_rate, args.icmp_rate, args.window)
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            an.feed(pkt)
    print(f"[*] Analyzed {an.total} packets from {path.name}")
    write_reports("pcap-analysis", {"pcap": str(path), "packets": an.total}, an.findings())


def run_monitor(args):
    from scapy.all import sniff
    an = TrafficAnalyzer(args.scan_ports, args.syn_rate, args.icmp_rate, args.window)
    print(f"[*] Sniffing on {args.iface or 'default interface'} for {args.duration}s (needs root/admin)...")
    try:
        sniff(iface=args.iface, prn=an.feed, store=False, timeout=args.duration)
    except PermissionError:
        sys.exit("Permission denied. Run with sudo / as Administrator.")
    except Exception as e:
        sys.exit(f"Sniffing failed: {e}\nOn Windows install Npcap (https://npcap.com).")
    print(f"[*] Captured {an.total} packets")
    write_reports("live-monitor", {"iface": args.iface, "packets": an.total}, an.findings())


def run_demo(args):
    """Create a synthetic pcap containing a port scan + SYN flood and analyze it."""
    from scapy.all import wrpcap
    from scapy.layers.inet import ICMP, IP, TCP
    pkts, t = [], time.time()
    for i, port in enumerate(range(1, 61)):                       # port scan
        p = IP(src="10.0.0.66", dst="10.0.0.5") / TCP(sport=40000, dport=port, flags="S")
        p.time = t + i * 0.01
        pkts.append(p)
    for i in range(300):                                          # SYN flood
        p = IP(src="10.0.0.99", dst="10.0.0.5") / TCP(sport=1000 + i, dport=80, flags="S")
        p.time = t + 1 + i * 0.005
        pkts.append(p)
    for i in range(150):                                          # ping sweep/flood
        p = IP(src="10.0.0.77", dst="10.0.0.5") / ICMP()
        p.time = t + 2 + i * 0.01
        pkts.append(p)
    tmp = Path(tempfile.gettempdir()) / "recon_demo.pcap"
    wrpcap(str(tmp), pkts)
    print(f"[*] Demo capture written to {tmp}")
    args.pcap, args.scan_ports, args.syn_rate, args.icmp_rate, args.window = str(tmp), 15, 100, 100, 10
    run_analyze(args)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def write_reports(kind, meta, findings):
    REPORT_DIR.mkdir(exist_ok=True)
    findings = sorted(findings, key=lambda f: -SEV_ORDER[f["severity"]])
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    data = {"generated": datetime.now().isoformat(timespec="seconds"),
            "type": kind, "meta": meta, "findings": findings}
    jpath = REPORT_DIR / f"{kind}-{stamp}.json"
    hpath = REPORT_DIR / f"{kind}-{stamp}.html"
    jpath.write_text(json.dumps(data, indent=2))
    colors = {"CRITICAL": "#9b1c1c", "HIGH": "#c05621", "MEDIUM": "#b7791f",
              "LOW": "#2b6cb0", "INFO": "#4a5568"}
    rows = "".join(
        f"<tr><td style='color:{colors[f['severity']]};font-weight:700'>{f['severity']}</td>"
        f"<td>{html.escape(str(f['host']))}</td><td>{f['port'] or '-'}</td>"
        f"<td>{html.escape(f['detail'])}</td><td>{html.escape(f['advice'])}</td></tr>"
        for f in findings)
    hpath.write_text(f"""<!doctype html><meta charset=utf-8><title>Recon Report</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#1a202c;color:#fff}}</style>
<h1>Recon Report - {kind}</h1><p>Generated {data['generated']}</p>
<pre>{html.escape(json.dumps(meta, indent=2))}</pre>
<table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th><th>Remediation</th></tr>{rows}</table>""")
    print(f"\n=== {len(findings)} finding(s) ===")
    for f in findings:
        print(f"[{f['severity']:<8}] {f['host']}:{f['port'] or '-'}  {f['detail']}")
    print(f"\nReports saved: {jpath}  |  {hpath}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Port/vulnerability scan (Nmap or fallback)")
    s.add_argument("target", help="IP, hostname or CIDR (e.g. 192.168.1.0/24)")
    s.add_argument("--ports", default="1-1024")
    s.add_argument("--vuln", action="store_true", help="Run Nmap vuln scripts (slow)")
    s.add_argument("--no-nmap", action="store_true", help="Force the Python fallback scanner")
    s.add_argument("--authorized", action="store_true", help="I have permission to scan non-private targets")
    s.set_defaults(fn=run_scan)

    def add_thresholds(p):
        p.add_argument("--scan-ports", type=int, default=15, help="distinct ports/window to flag a scan")
        p.add_argument("--syn-rate", type=int, default=100, help="SYNs/window to flag a flood")
        p.add_argument("--icmp-rate", type=int, default=100, help="ICMP echoes/window to flag a flood")
        p.add_argument("--window", type=int, default=10, help="window in seconds")

    a = sub.add_parser("analyze", help="Analyze a Wireshark .pcap/.pcapng file")
    a.add_argument("pcap")
    add_thresholds(a)
    a.set_defaults(fn=run_analyze)

    m = sub.add_parser("monitor", help="Live traffic monitoring (root required)")
    m.add_argument("--iface")
    m.add_argument("--duration", type=int, default=60)
    add_thresholds(m)
    m.set_defaults(fn=run_monitor)

    d = sub.add_parser("demo", help="Self-contained demo using a synthetic attack capture")
    d.set_defaults(fn=run_demo)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
