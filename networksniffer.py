# network_sniffer_demo.py

from scapy.all import IP, TCP, UDP, ICMP
from collections import Counter
import matplotlib
matplotlib.use('Agg')  # Use non-GUI backend for thread safety
import matplotlib.pyplot as plt
import threading
import time

# -------------------------
# Globals
# -------------------------
packet_counts = Counter()
suspicious_ips = Counter()
lock = threading.Lock()
SUSPICIOUS_THRESHOLD = 5

# -------------------------
# Generate simulated traffic
# -------------------------
simulated_packets = []

for i in range(50):
    simulated_packets.append(IP(src=f"192.168.1.{i%5}", dst="192.168.1.100")/TCP())
    simulated_packets.append(IP(src=f"10.0.0.{i%3}", dst="10.0.0.1")/UDP())
    if i % 5 == 0:
        simulated_packets.append(IP(src=f"172.16.0.{i%4}", dst="172.16.0.1")/ICMP())

# -------------------------
# Packet processing
# -------------------------
def packet_callback(packet):
    with lock:
        if packet.haslayer(TCP):
            packet_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            packet_counts['UDP'] += 1
        elif packet.haslayer(ICMP):
            packet_counts['ICMP'] += 1
        else:
            packet_counts['Other'] += 1

        src_ip = packet[IP].src
        suspicious_ips[src_ip] += 1

# -------------------------
# Reporting function
# -------------------------
def print_report():
    while True:
        time.sleep(5)  # Update every 5 seconds
        with lock:
            if sum(packet_counts.values()) == 0:
                continue

            print("\n=== Mini Network Packet Sniffer Report ===")
            print(f"Total Packets Captured: {sum(packet_counts.values())}")
            for pkt_type, count in packet_counts.items():
                print(f"{pkt_type} Packets: {count}")

            # Flag suspicious IPs
            flagged = [ip for ip, count in suspicious_ips.items() if count > SUSPICIOUS_THRESHOLD]
            if flagged:
                print("Suspicious IPs detected:")
                for ip in flagged:
                    print(f"{ip} -> {suspicious_ips[ip]} packets")
            else:
                print("No suspicious IPs detected.")

            # Save pie chart to PNG
            labels = packet_counts.keys()
            sizes = packet_counts.values()
            colors = ['skyblue', 'orange', 'green', 'red']
            plt.figure(figsize=(5,5))
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=colors)
            plt.title("Packet Type Distribution")
            plt.savefig("packet_distribution.png")
            plt.close()

# -------------------------
# Main execution
# -------------------------
if __name__ == "__main__":
    print("=== Mini Network Packet Sniffer (Simulated Traffic) Started ===")

    # Start report thread
    report_thread = threading.Thread(target=print_report, daemon=True)
    report_thread.start()

    # Feed simulated packets
    for packet in simulated_packets:
        packet_callback(packet)
        time.sleep(0.1)  # Simulate real traffic

    # Wait a bit to ensure last report is generated
    time.sleep(6)
    print("\n=== Simulation Completed ===")
    print("Pie chart saved as 'packet_distribution.png'")
