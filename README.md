# Cybersecurity Reconnaissance Toolkit

Python framework that integrates **Nmap** (vulnerability/service scans) and **Wireshark** captures
(traffic analysis) to detect suspicious network activity and produce remediation reports.

> **Legal:** only scan or monitor systems you own or have written permission to test.
> Public IPs are blocked unless you pass `--authorized`.

## Features
- Nmap-based service/version detection and `--vuln` script scans (auto-fallback to a built-in TCP scanner if Nmap isn't installed)
- Risk rating of exposed services (Telnet, SMB, RDP, Redis, ...) with remediation advice
- Detects **port scans, SYN floods, ICMP floods and ARP spoofing** from live traffic or Wireshark `.pcap/.pcapng` files
- JSON + HTML reports sorted by severity

## Setup
```bash
pip install -r requirements.txt
```

## Usage
```bash
python recon_toolkit.py demo                              # no setup needed: synthetic attack capture
python recon_toolkit.py scan 127.0.0.1 --ports 1-1024
python recon_toolkit.py scan 192.168.1.0/24 --ports 22,80,443,3389 --vuln
python recon_toolkit.py analyze capture.pcapng            # file saved from Wireshark
sudo python recon_toolkit.py monitor --iface eth0 --duration 120
```
Reports are saved in `reports/` (open the `.html` file in a browser).

## How detection works
| Threat | Heuristic |
|---|---|
| Port scan | One source sends SYNs to >= 15 distinct ports in a 10 s window |
| SYN flood | >= 100 SYN packets from one source in a 10 s window |
| ICMP flood | >= 100 echo requests from one source in a 10 s window |
| ARP spoofing | One IP announced by more than one MAC address |

Thresholds are tunable (`--scan-ports`, `--syn-rate`, `--icmp-rate`, `--window`).
