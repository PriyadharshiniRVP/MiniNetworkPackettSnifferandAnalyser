# Mini Network Packet Sniffer & Analyzer

A Python project that simulates network traffic monitoring, analyzes packet types, detects suspicious IP activity, and generates visualization reports. Designed to demonstrate **network monitoring, cybersecurity awareness, and Python scripting**.

## Features

- Simulates TCP, UDP, and ICMP network traffic.
- Counts packets by type (TCP/UDP/ICMP/Other).
- Detects suspicious IP addresses based on traffic thresholds.
- Generates pie chart visualization of packet distribution.
- Fully automated and demo-ready on Windows (no admin or Npcap required).

## How It Works

1. The script generates simulated network traffic.
2. Packets are analyzed in real-time:
   - Counts are maintained for each protocol type.
   - Source IPs are tracked to identify potential suspicious activity.
3. Every 5 seconds, a console report prints:
   - Total packets captured
   - Count of each packet type
   - Suspicious IPs exceeding the threshold
4. **A pie chart of packet type distribution is generated and attached** as `packet_distribution.png` for easy visualization.

## Getting Started

### Prerequisites

- Python 3.8+
- Libraries: `scapy`, `matplotlib`

Install dependencies:
```bash
pip install scapy matplotlib
