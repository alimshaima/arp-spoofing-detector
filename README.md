# Advanced Packet Sniffer + ARP Spoofing Detector

## Description
A real-time network monitoring tool using Python and Scapy. Captures TCP, UDP, ICMP, and ARP packets, detects ARP spoofing attacks by tracking IP-to-MAC mapping anomalies, and logs alerts for forensic analysis.

## Problem Statement
ARP spoofing (ARP poisoning) allows attackers on a local network to intercept, modify, or redirect traffic, enabling man-in-the-middle attacks. Most basic tools capture ARP traffic without detecting anomalies in real time.

## Features
- Capture live TCP, UDP, ICMP, and ARP packets
- Detect ARP spoofing using IP-to-MAC mapping anomalies
- Log suspicious events to `arp_alerts.txt`
- Real-time console output
- Graceful exit with Ctrl+C

## Tech Stack
- Python 3.x
- Scapy

## Installation

```bash
# Clone repository
git clone https://github.com/alimshaima/arp-spoofing-detector.git

# Navigate to folder
cd arp-spoofing-detector

# Install Scapy
pip install -r requirements.txt
```

### Usage
Ethical Note: Run only on owned or authorized networks.

# Run with administrator/root privileges
sudo python sniffer.py   # Linux/Mac
# OR
python sniffer.py        # Windows (as Administrator)

### Sample Output
========================================
  Advanced Packet Sniffer
  + ARP Spoofing Detector
  Running... Press Ctrl+C to stop
========================================
[*] New device | IP: 192.168.1.1 | MAC: aa:bb:cc:dd:ee:ff
[+] Normal ARP | IP: 192.168.1.2 | MAC: 11:22:33:44:55:66
[TCP] 192.168.1.5 -> 142.250.185.46 | Port: 443

[!] ARP SPOOFING DETECTED!
    IP Address : 192.168.1.1
    Old MAC    : aa:bb:cc:dd:ee:ff
    New MAC    : 00:11:22:33:44:55

### Output Files
arp_alerts.txt - Timestamped log of all ARP spoofing attempts

### Author
Alima Shaima
