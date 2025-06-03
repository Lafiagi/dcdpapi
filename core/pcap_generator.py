#!/usr/bin/env python3
"""
PCAP File Generator for Testing Network Analysis Application
This script generates synthetic network traffic in PCAP format for testing purposes.
"""

from scapy.all import *
import random
import time
from datetime import datetime, timedelta


def generate_normal_traffic():
    """Generate normal web browsing traffic"""
    packets = []

    # Simulate web traffic
    for i in range(100):
        # HTTP requests
        pkt = (
            IP(src=f"192.168.1.{random.randint(2, 254)}", dst="8.8.8.8")
            / TCP(sport=random.randint(1024, 65535), dport=80)
            / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        packets.append(pkt)

        # DNS queries
        if i % 10 == 0:
            dns_pkt = (
                IP(src=f"192.168.1.{random.randint(2, 254)}", dst="8.8.8.8")
                / UDP(sport=random.randint(1024, 65535), dport=53)
                / DNS(rd=1, qd=DNSQR(qname="example.com"))
            )
            packets.append(dns_pkt)

    return packets


def generate_port_scan_traffic():
    """Generate port scanning traffic"""
    packets = []
    attacker_ip = "10.0.0.100"
    target_ip = "192.168.1.50"

    # TCP SYN scan across multiple ports
    for port in range(20, 1024, 10):
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=port, flags="S"
        )
        packets.append(pkt)

        # Some RST responses
        if random.random() > 0.7:
            rst_pkt = IP(src=target_ip, dst=attacker_ip) / TCP(
                sport=port, dport=pkt[TCP].sport, flags="RA"
            )
            packets.append(rst_pkt)

    return packets


def generate_ddos_traffic():
    """Generate DDoS-like traffic"""
    packets = []
    target_ip = "192.168.1.100"

    # High volume traffic from multiple sources
    for i in range(500):
        src_ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        pkt = IP(src=src_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S"
        )
        packets.append(pkt)

    return packets


def generate_dns_tunneling():
    """Generate DNS tunneling traffic"""
    packets = []

    # Suspicious DNS queries with encoded data
    suspicious_domains = [
        "aGVsbG8gd29ybGQ.tunnel.com",
        "dGhpcyBpcyBhIHRlc3Q.tunnel.com",
        "bWFsd2FyZSBkYXRh.tunnel.com",
        "ZXhmaWx0cmF0aW9u.tunnel.com",
    ]

    for i in range(50):
        domain = random.choice(suspicious_domains)
        pkt = (
            IP(src=f"192.168.1.{random.randint(2, 254)}", dst="8.8.8.8")
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        packets.append(pkt)

    return packets


def generate_data_exfiltration():
    """Generate data exfiltration traffic"""
    packets = []
    internal_ip = "192.168.1.25"
    external_ip = "203.0.113.100"  # RFC5737 test address

    # Large outbound transfers
    for i in range(20):
        # Large payload
        payload = b"A" * random.randint(1000, 8000)
        pkt = (
            IP(src=internal_ip, dst=external_ip)
            / TCP(sport=random.randint(1024, 65535), dport=443)
            / Raw(payload)
        )
        packets.append(pkt)

    return packets


def create_test_pcap(filename="test_sample.pcap", include_threats=True):
    """Create a comprehensive test PCAP file"""
    print(f"Generating test PCAP file: {filename}")

    all_packets = []

    # Add normal traffic
    print("Adding normal traffic...")
    all_packets.extend(generate_normal_traffic())

    if include_threats:
        print("Adding threat patterns...")
        # Add various threat patterns
        all_packets.extend(generate_port_scan_traffic())
        all_packets.extend(generate_ddos_traffic())
        all_packets.extend(generate_dns_tunneling())
        all_packets.extend(generate_data_exfiltration())

    # Shuffle packets to make it more realistic
    random.shuffle(all_packets)

    # Add timestamps
    base_time = time.time()
    for i, pkt in enumerate(all_packets):
        pkt.time = base_time + (i * 0.1)  # 100ms intervals

    # Write to PCAP file
    wrpcap(filename, all_packets)
    print(f"Created {filename} with {len(all_packets)} packets")

    return filename


def create_clean_pcap(filename="clean_sample.pcap"):
    """Create a PCAP with only normal traffic"""
    print(f"Generating clean PCAP file: {filename}")
    packets = generate_normal_traffic()

    # Add timestamps
    base_time = time.time()
    for i, pkt in enumerate(packets):
        pkt.time = base_time + (i * 0.2)

    wrpcap(filename, packets)
    print(f"Created {filename} with {len(packets)} packets")
    return filename


def analyze_pcap(filename):
    """Basic analysis of the generated PCAP"""
    print(f"\nAnalyzing {filename}:")
    packets = rdpcap(filename)

    print(f"Total packets: {len(packets)}")

    # Protocol distribution
    protocols = {}
    for pkt in packets:
        if pkt.haslayer(TCP):
            protocols["TCP"] = protocols.get("TCP", 0) + 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] = protocols.get("UDP", 0) + 1
        elif pkt.haslayer(ICMP):
            protocols["ICMP"] = protocols.get("ICMP", 0) + 1

    print("Protocol distribution:")
    for proto, count in protocols.items():
        print(f"  {proto}: {count}")

    # IP addresses
    src_ips = set()
    dst_ips = set()
    for pkt in packets:
        if pkt.haslayer(IP):
            src_ips.add(pkt[IP].src)
            dst_ips.add(pkt[IP].dst)

    print(f"Unique source IPs: {len(src_ips)}")
    print(f"Unique destination IPs: {len(dst_ips)}")


if __name__ == "__main__":
    print("PCAP Test File Generator")
    print("=" * 40)

    # Check if scapy is available
    try:
        from scapy.all import *

        print("Scapy found - generating PCAP files...")

        # Create test files
        test_file = create_test_pcap("comprehensive_test.pcap", include_threats=True)
        clean_file = create_clean_pcap("clean_traffic.pcap")

        # Analyze the files
        analyze_pcap(test_file)
        analyze_pcap(clean_file)

        print("\nTest files created successfully!")
        print("Files generated:")
        print(f"  - {test_file} (includes threat patterns)")
        print(f"  - {clean_file} (clean traffic only)")

    except ImportError:
        print("Error: Scapy not found. Install with: pip install scapy")
        print("\nAlternatively, use the wget commands below to download sample files:")
        print("\n# Download sample PCAP files from public repositories:")
        print("wget https://github.com/automayt/ICS-pcap/raw/master/modbus/modbus.pcap")
        print(
            "wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap"
        )
        print(
            "wget https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.pcap"
        )
