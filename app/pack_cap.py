from scapy.all import sniff, IP, TCP, UDP, ICMPv6EchoRequest, get_if_list, IPv6
from scapy.layers.inet import ICMP
from colorama import Fore, Style
from scapy.layers.l2 import Ether

from app import db
from app.capture_controller import save_alert_to_db
from scapy.layers.l2 import ARP
from app.get_m_ip import *
interfaces = get_if_list()
# malicious_ips={"192.160.2.2":"hritik patidar",}
print("Available network interfaces:", interfaces)
from scapy.layers.dns import DNSQR
from app.config_loader import load_config
from collections import defaultdict, deque, Counter
from queue import Queue
import time
# Load config from file
config = load_config("config.txt")

# MAC Flooding
MAC_FLOOD_WINDOW = config.get("MAC_FLOOD_WINDOW", 10)                # seconds
MAC_FLOOD_THRESHOLD = config.get("MAC_FLOOD_THRESHOLD", 50)          # unique MACs in window
mac_seen = defaultdict(lambda: deque())  # src_ip -> deque of (mac, timestamp)

# ICMP Smurf Attack Detection
ICMP_SMURF_THRESHOLD = config.get("ICMP_SMURF_THRESHOLD", 10)        # packets in time window
ICMP_SMURF_WINDOW = config.get("ICMP_SMURF_WINDOW", 5)               # seconds
icmp_broadcast_tracker = deque()  # list of (timestamp, src_ip)

# IP Fragmentation Attack Detection
FRAG_THRESHOLD = config.get("FRAG_THRESHOLD", 10)                    # fragments allowed
FRAG_WINDOW = config.get("FRAG_WINDOW", 5)                           # seconds
fragment_count = defaultdict(deque)  # {src_ip: deque of timestamps}

# TCP RST Flood Detection
RST_FLOOD_THRESHOLD = config.get("RST_FLOOD_THRESHOLD", 100)        # packets/sec
RST_WINDOW_SECONDS = config.get("RST_WINDOW_SECONDS", 1)            # window
rst_packet_count = defaultdict(deque)

# UDP Flood Detection
UDP_THRESHOLD = config.get("UDP_THRESHOLD", 100)                     # packets
UDP_TIME_WINDOW = config.get("UDP_TIME_WINDOW", 5)                   # seconds
udp_packet_log = defaultdict(deque)

# DNS Tunneling Detection
QUERY_RATE_THRESHOLD = config.get("QUERY_RATE_THRESHOLD", 20)       # max queries/domain
TIME_WINDOW_DNS = config.get("TIME_WINDOW_DNS", 60)                 # seconds
dns_query_counts = defaultdict(int)
dns_last_seen = {}

# ARP Spoofing
arp_table = {}  # ip -> mac

# Large ICMP Packet Flood
ICMP_LARGE_THRESHOLD = config.get("ICMP_LARGE_THRESHOLD", 1000)      # size in bytes
ICMP_ALERT_LIMIT = config.get("ICMP_ALERT_LIMIT", 5)                 # alert threshold
ICMP_ALERT_WINDOW = config.get("ICMP_ALERT_WINDOW", 7)               # seconds
icmp_alert_times = deque(maxlen=100)

# SYN Scan Detection
SYN_THRESHOLD = config.get("SYN_THRESHOLD", 30)                              # SYN count per window
TIME_WINDOW = config.get("TIME_WINDOW", 6)                           # seconds
syn_count = Counter()
start_time = time.time()

# Live Packet Display Rate Limiting
MAX_PACKETS_PER_SECOND = config.get("MAX_PACKETS_PER_SECOND", 5)     # UI rate limit
last_sent_time = time.time()
packet_count = 0
print_packet = True
live_packet_queue = Queue()

# Packet Rate (DoS Detection)
PACKET_RATE_THRESHOLD_DOS = config.get("PACKET_RATE_THRESHOLD_DOS", 200)  # packets/sec/IP
RATE_TIME_WINDOW_DOS = config.get("RATE_TIME_WINDOW_DOS", 1)              # seconds
packet_rate_map = defaultdict(deque)


# TCP Port Scan Detection
TCP_SCAN_WINDOW = config.get("TCP_SCAN_WINDOW", 10)  # seconds
TCP_SCAN_THRESHOLD = config.get("TCP_SCAN_THRESHOLD", 15)  # unique ports in time window
tcp_scan_log = defaultdict(deque)  # (src_ip, dst_ip) -> deque of (port, timestamp)


# Packet storage (for further processing or export)
packet_data = []


def process_packet(packet):
    global start_time, last_sent_time, packet_count
    # print(malicious_ips)
    try:

        # if print_packet:
        #     current_time = time.time()
        #     if current_time - last_sent_time >= 1:
        #         last_sent_time = current_time
        #         packet_count = 0
        #
        #     if packet_count < MAX_PACKETS_PER_SECOND:
        #         src_ip = dst_ip = proto = "Unknown"
        #         pkt_size = len(packet)
        #
        #         if packet.haslayer(IP):
        #             src_ip = packet[IP].src
        #             dst_ip = packet[IP].dst
        #             proto = packet[IP].proto
        #         elif packet.haslayer(IPv6):
        #             src_ip = packet[IPv6].src
        #             dst_ip = packet[IPv6].dst
        #             proto = "IPv6"
        #
        #         if packet.haslayer(TCP):
        #             proto = "TCP"
        #         elif packet.haslayer(UDP):
        #             proto = "UDP"
        #         elif packet.haslayer(ICMP):
        #             proto = "ICMP"
        #
        #         summary = f"{src_ip} → {dst_ip} | Protocol: {proto} | Size: {pkt_size} bytes"
        #         print(summary)
        #
        #         live_packet_queue.put(summary)
        #         packet_count += 1
        #     else:
        #         # Exceeded rate limit, skip pushing to queue
        #         pass
        # SYN Scan Detection
        if print_packet:
            try:
                current_time = time.time()
                if current_time - last_sent_time >= 1:
                    last_sent_time = current_time
                    packet_count = 0

                if packet_count < MAX_PACKETS_PER_SECOND:
                    pkt_size = len(packet)

                    # Fix: Get class names of layers
                    layer_names = [layer.__class__.__name__ for layer in packet.layers()]
                    proto = " > ".join(layer_names)

                    summary = f"{packet.summary()} | Layers: {proto} | Size: {pkt_size} bytes"
                    print(summary)

                    live_packet_queue.put(summary)
                    packet_count += 1

            except Exception as e:
                print(f"[WARNING] Packet skipped: {e}")

        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN
            src_ip = packet[IP].src
            syn_count[src_ip] += 1

            if time.time() - start_time > TIME_WINDOW:
                for ip, count in syn_count.items():
                    if count > SYN_THRESHOLD:
                        msg = f"[ALERT] Possible SYN scan from {ip} ({count} SYNs in {TIME_WINDOW}s)"
                        print(Fore.RED + msg + Style.RESET_ALL)
                        save_alert_to_db(msg)
                syn_count.clear()
                start_time = time.time()

        #large icmp packet alert
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            pkt_size = len(packet)
            if pkt_size > ICMP_LARGE_THRESHOLD:
                current_time = time.time()
                icmp_alert_times.append(current_time)

                # Remove timestamps older than 5 seconds
                while icmp_alert_times and current_time - icmp_alert_times[0] > ICMP_ALERT_WINDOW:
                    icmp_alert_times.popleft()

                if len(icmp_alert_times) > ICMP_ALERT_LIMIT:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    msg = f"[ALERT] ICMP Flood? More than {ICMP_ALERT_LIMIT} large ICMP packets in {ICMP_ALERT_WINDOW}s. Latest from {src_ip} to {dst_ip} ({pkt_size} bytes)"
                    print(Fore.RED + msg + Style.RESET_ALL)
                    save_alert_to_db(msg)
                    icmp_alert_times.clear()
                    # Large ICMPv6 Packet
        if packet.haslayer(ICMPv6EchoRequest) and packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            pkt_size = len(packet)
            if pkt_size > ICMP_LARGE_THRESHOLD:
                msg = f"[ALERT] Large ICMPv6 packet from {src_ip} to {dst_ip} ({pkt_size} bytes)"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)

        # General Packet Info and Large Packet Anomaly
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            pkt_size = len(packet)

            packet_data.append({
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": proto,
                "Packet Size": pkt_size
            })

            # if pkt_size > 1500:
            #     msg = f"[ALERT] Large packet from {src_ip} to {dst_ip} ({pkt_size} bytes)"
            #     print(Fore.RED + msg + Style.RESET_ALL)
            #     save_alert_to_db(msg)

        # Malicious IP Detection
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            malicious_ips=save_malicious_ips_to_file()
            if src_ip in malicious_ips:
                msg = f"[ALERT] Malicious source IP: {src_ip} ({malicious_ips[src_ip]})"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)

            if dst_ip in malicious_ips:
                msg = f"[ALERT] Malicious destination IP: {dst_ip} ({malicious_ips[dst_ip]})"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)


        # DNS Tunneling Detection
        if packet.haslayer(DNSQR) and packet.haslayer(UDP) and packet[UDP].dport == 53:
            domain = packet[DNSQR].qname.decode(errors='ignore').strip('.')
            labels = domain.split('.')

            # Rule 1: Check for long subdomains (base64-like strings)
            long_label = any(len(label) > 50 for label in labels)

            # Rule 2: Track how often this domain is queried
            current_time = time.time()
            if domain not in dns_last_seen:
                dns_last_seen[domain] = current_time
                dns_query_counts[domain] = 1
            else:
                if current_time - dns_last_seen[domain] < TIME_WINDOW_DNS:
                    dns_query_counts[domain] += 1
                else:
                    dns_query_counts[domain] = 1
                    dns_last_seen[domain] = current_time

            # Rule 3: Query rate too high in short time
            if dns_query_counts[domain] > QUERY_RATE_THRESHOLD or long_label:
                msg = f"[ALERT] Possible DNS tunneling detected: {domain} | Count: {dns_query_counts[domain]}"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)




        # ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            if src_ip in arp_table:
                # MAC mismatch? Possible spoofing
                if arp_table[src_ip] != src_mac:
                    msg = f"[ALERT] ARP spoofing detected! IP {src_ip} is now claiming MAC {src_mac} (was {arp_table[src_ip]})"
                    print(Fore.RED + msg + Style.RESET_ALL)
                    save_alert_to_db(msg)
            else:
                arp_table[src_ip] = src_mac

        # UDP Flood Detection
        if packet.haslayer(UDP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            now = time.time()

            udp_packet_log[src_ip].append(now)

            # Remove old entries outside the time window
            while udp_packet_log[src_ip] and now - udp_packet_log[src_ip][0] > UDP_TIME_WINDOW:
                udp_packet_log[src_ip].popleft()

            # Check if flood threshold exceeded
            if len(udp_packet_log[src_ip]) > UDP_THRESHOLD:
                msg = f"[ALERT] UDP Flood detected from {src_ip}: {len(udp_packet_log[src_ip])} packets in {UDP_TIME_WINDOW} seconds"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)
                udp_packet_log[src_ip].clear()

        # Packet Rate Monitoring (DoS Detection)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            current_time = time.time()

            # Add current timestamp
            packet_rate_map[src_ip].append(current_time)

            # Remove old timestamps outside the rate window
            while packet_rate_map[src_ip] and current_time - packet_rate_map[src_ip][0] > RATE_TIME_WINDOW_DOS:
                packet_rate_map[src_ip].popleft()

            # Check if rate exceeds threshold
            if len(packet_rate_map[src_ip]) > PACKET_RATE_THRESHOLD_DOS:
                msg = f"[ALERT] DoS Suspected: High packet rate from {src_ip} - {len(packet_rate_map[src_ip])} packets in {RATE_TIME_WINDOW_DOS}s"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)
                packet_rate_map[src_ip].clear()  # Optional: to avoid repeated alerts

        # TCP Reset Flood Detection
        if packet.haslayer(IP) and packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 0x04:  # RST flag (0x04)
                src_ip = packet[IP].src
                current_time = time.time()

                rst_packet_count[src_ip].append(current_time)

                # Remove timestamps older than the time window
                while rst_packet_count[src_ip] and current_time - rst_packet_count[src_ip][0] > RST_WINDOW_SECONDS:
                    rst_packet_count[src_ip].popleft()

                # Check if count exceeds threshold
                if len(rst_packet_count[src_ip]) > RST_FLOOD_THRESHOLD:
                    msg = f"[ALERT] TCP RST Flood suspected from {src_ip} - {len(rst_packet_count[src_ip])} RSTs in {RST_WINDOW_SECONDS}s"
                    print(Fore.RED + msg + Style.RESET_ALL)
                    save_alert_to_db(msg)
                    rst_packet_count[src_ip].clear()  # Avoid repeating the alert constantly

        # IP Fragmentation Attack Detection
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            if ip_layer.flags == 1 or ip_layer.frag > 0:
                src_ip = ip_layer.src
                current_time = time.time()

                fragment_count[src_ip].append(current_time)

                # Remove old timestamps outside the window
                while fragment_count[src_ip] and current_time - fragment_count[src_ip][0] > FRAG_WINDOW:
                    fragment_count[src_ip].popleft()

                if len(fragment_count[src_ip]) > FRAG_THRESHOLD:
                    msg = f"[ALERT] Possible IP Fragmentation attack from {src_ip} - {len(fragment_count[src_ip])} fragments in {FRAG_WINDOW}s"
                    print(Fore.RED + msg + Style.RESET_ALL)
                    save_alert_to_db(msg)
                    fragment_count[src_ip].clear()

        # Smurf Attack Detection
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            # ICMP Echo Request (ping)
            if icmp_layer.type == 8:
                dst_ip = ip_layer.dst
                src_ip = ip_layer.src
                current_time = time.time()

                # Check for broadcast pattern (e.g., ends with .255 or .0)
                if dst_ip.endswith('.255') or dst_ip.endswith('.0'):
                    icmp_broadcast_tracker.append((current_time, src_ip))

                    # Remove old entries
                    while icmp_broadcast_tracker and current_time - icmp_broadcast_tracker[0][0] > ICMP_SMURF_WINDOW:
                        icmp_broadcast_tracker.popleft()

                    # Count how many pings went to broadcast recently
                    if len(icmp_broadcast_tracker) > ICMP_SMURF_THRESHOLD:
                        msg = f"[ALERT] Possible Smurf Attack: {len(icmp_broadcast_tracker)} ICMP Echo Requests to broadcast addresses in {ICMP_SMURF_WINDOW}s. Latest from {src_ip}"
                        print(Fore.RED + msg + Style.RESET_ALL)
                        save_alert_to_db(msg)
                        icmp_broadcast_tracker.clear()

        # Land Attack Detection
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            if ip_layer.src == ip_layer.dst and tcp_layer.sport == tcp_layer.dport:
                msg = f"[ALERT] Land Attack detected: Source and Destination IP/Port are the same ({ip_layer.src}:{tcp_layer.sport})"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)

        # MAC Flooding Detection
        if packet.haslayer(Ether) and packet.haslayer(IP):
            src_mac = packet[Ether].src
            src_ip = packet[IP].src
            now = time.time()

            # Record new MAC usage for this IP
            mac_queue = mac_seen[src_ip]
            mac_queue.append((src_mac, now))

            # Remove MACs outside the time window
            while mac_queue and now - mac_queue[0][1] > MAC_FLOOD_WINDOW:
                mac_queue.popleft()

            # Count unique MACs in the window
            unique_macs = set(mac for mac, _ in mac_queue)

            if len(unique_macs) > MAC_FLOOD_THRESHOLD:
                msg = f"[ALERT] MAC Flooding attack suspected from {src_ip}: {len(unique_macs)} unique MACs in {MAC_FLOOD_WINDOW}s"
                print(Fore.RED + msg + Style.RESET_ALL)
                save_alert_to_db(msg)
                mac_queue.clear()



        # TCP Port Scan Detection (SYN Scan Pattern)
        if packet.haslayer(IP) and packet.haslayer(TCP):
            tcp = packet[TCP]
            ip = packet[IP]

            if tcp.flags == "S":  # SYN only
                key = (ip.src, ip.dst)
                now = time.time()
                tcp_scan_log[key].append((tcp.dport, now))

                # Remove old entries
                while tcp_scan_log[key] and now - tcp_scan_log[key][0][1] > TCP_SCAN_WINDOW:
                    tcp_scan_log[key].popleft()

                # Count unique destination ports
                unique_ports = {port for port, _ in tcp_scan_log[key]}
                if len(unique_ports) > TCP_SCAN_THRESHOLD:
                    msg = f"[ALERT] TCP Port Scan detected from {ip.src} to {ip.dst} on ports: {sorted(unique_ports)}"
                    print(Fore.RED + msg + Style.RESET_ALL)
                    save_alert_to_db(msg)
                    tcp_scan_log[key].clear()  # Optional: Reset after detection





    except Exception as e:
        print(Fore.YELLOW + f"[WARNING] Packet skipped: {e}" + Style.RESET_ALL)


def start_sniffing(interface):
    print(f"[*] Sniffing started on: {interface}")
    sniff(iface=interface, prn=process_packet, store=0)


# 👇 Uncomment and run this with your real interface name
# start_sniffing("Wi-Fi")  # or "Ethernet"
