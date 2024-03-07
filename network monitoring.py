from scapy.all import *

# Define a function to detect and mitigate network attacks
def detect_and_mitigate(packet):
    # Check for SYN flood attack
    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:
        if packet[TCP].dport in [80, 443]:  # Common web server ports
            if packet[IP].src in syn_flood_sources:
                syn_flood_sources[packet[IP].src] += 1
                if syn_flood_sources[packet[IP].src] > SYN_FLOOD_THRESHOLD:
                    # Mitigate SYN flood attack by blocking the source IP
                    print(f"Detected SYN flood attack from {packet[IP].src}. Blocking source IP.")
                    block_ip(packet[IP].src)
            else:
                syn_flood_sources[packet[IP].src] = 1

    # Check for port scanning
    if packet.haslayer(TCP) and packet[TCP].flags & 0x12:
        if packet[IP].src in port_scan_sources:
            port_scan_sources[packet[IP].src].add(packet[TCP].dport)
            if len(port_scan_sources[packet[IP].src]) > PORT_SCAN_THRESHOLD:
                # Mitigate port scanning attack by blocking the source IP
                print(f"Detected port scanning from {packet[IP].src}. Blocking source IP.")
                block_ip(packet[IP].src)
        else:
            port_scan_sources[packet[IP].src] = set([packet[TCP].dport])

# Function to block an IP address
def block_ip(ip_address):
    # Implement your IP blocking logic here
    # e.g., update firewall rules, send alerts, etc.
    print(f"Blocking IP address: {ip_address}")

# Initialize attack detection thresholds
SYN_FLOOD_THRESHOLD = 100  # Adjust as needed
PORT_SCAN_THRESHOLD = 10   # Adjust as needed

# Initialize attack tracking dictionaries
syn_flood_sources = {}
port_scan_sources = {}

# Start network monitoring
print("Starting network monitoring...")
sniff(prn=detect_and_mitigate, store=0)