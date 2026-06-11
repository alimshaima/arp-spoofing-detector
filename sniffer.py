# Advanced Packet Sniffer + ARP Spoofing Detector
from scapy.all import sniff, ARP
import datetime

# Stores IP -> MAC mappings
arp_table = {}

def log_alert(ip, old_mac, new_mac):
    """Log ARP spoofing alerts to file"""
    with open("arp_alerts.txt", "a") as f:
        f.write(f"\n[ALERT] {datetime.datetime.now()}\n")
        f.write(f"  IP      : {ip}\n")
        f.write(f"  Old MAC : {old_mac}\n")
        f.write(f"  New MAC : {new_mac}\n")
        f.write("-" * 40 + "\n")

def detect_arp_spoof(packet):
    """Detect ARP spoofing attacks"""
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        
        if ip in arp_table:
            if arp_table[ip] != mac:
                print(f"\n[!] ARP SPOOFING DETECTED!")
                print(f"    IP Address : {ip}")
                print(f"    Old MAC    : {arp_table[ip]}")
                print(f"    New MAC    : {mac}")
                print(f"    Time       : {datetime.datetime.now()}")
                log_alert(ip, arp_table[ip], mac)
            else:
                print(f"[+] Normal ARP | IP: {ip} | MAC: {mac}")
        else:
            arp_table[ip] = mac
            print(f"[*] New device | IP: {ip} | MAC: {mac}")

def analyze_packet(packet):
    """Analyze all packet types"""
    if packet.haslayer(ARP):
        detect_arp_spoof(packet)
    
    elif packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        
        if packet.haslayer("TCP"):
            print(f"[TCP]  {ip_src} -> {ip_dst} | Port: {packet['TCP'].dport}")
        
        elif packet.haslayer("UDP"):
            print(f"[UDP]  {ip_src} -> {ip_dst} | Port: {packet['UDP'].dport}")
        
        elif packet.haslayer("ICMP"):
            print(f"[ICMP] {ip_src} -> {ip_dst}")

# Main - Start the tool
print("=" * 40)
print("  Advanced Packet Sniffer")
print("  + ARP Spoofing Detector")
print("  Running... Press Ctrl+C to stop")
print("=" * 40)

try:
    sniff(prn=analyze_packet, store=0)
except KeyboardInterrupt:
    print("\n" + "=" * 40)
    print("  Tool stopped by user")
    print(f"  Devices monitored: {len(arp_table)}")
    print("  Check arp_alerts.txt for alerts")
    print("=" * 40)
