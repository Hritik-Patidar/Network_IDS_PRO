import traceback

from more_itertools.more import extract
from scapy.all import sniff, IP, TCP, UDP, ICMPv6EchoRequest, get_if_list, IPv6
from scapy.layers.inet import ICMP
from colorama import Fore, Style
from scapy.layers.l2 import Ether

from app.data.config_loader import load_config
from app.stats.stats_monitor import stats
from app.utils.deduplicator import AlertDeduplicator
from app.capture_controller import save_alert_to_db
from scapy.layers.l2 import ARP

from app.utils.extract_attributes import extract_attributes
from app.utils.get_m_ip import *
from scapy.utils import wrpcap
from scapy.layers.dns import DNSQR
from collections import defaultdict, deque, Counter
from queue import Queue
import time
check_duplicate=AlertDeduplicator(30) #time in second for duplicate alert expire

# Load config from file
config = load_config()
rule = {"tcp": {}, "udp": {}}

def build_rule_key(detection_rule):
    fields = [
        detection_rule.src_ip,
        detection_rule.dst_ip,
        detection_rule.src_port,
        detection_rule.dst_port
    ]
    if detection_rule.protocol == "tcp":
        fields.append(detection_rule.tcp_flags)
    return ":".join(fields)

def reload_rules_from_db():
    global rule
    loaded_rules = {"tcp": {}, "udp": {}}
    try:
        from app import create_app
        from app.data.models import DetectionRule

        flask_app = create_app()
        with flask_app.app_context():
            detection_rules = DetectionRule.query.filter_by(enabled=True).all()
            for detection_rule in detection_rules:
                protocol = detection_rule.protocol.lower()
                if protocol in loaded_rules:
                    loaded_rules[protocol][build_rule_key(detection_rule)] = detection_rule.message
        rule = loaded_rules
    except Exception as e:
        print(f"[WARNING] Unable to load detection rules from DB: {e}")
    return rule

def handle_rule_match(protocol, rule_hash, message):
    alert_message = f"[ALERT] Rule matched [{protocol}] {rule_hash}: {message}"
    if check_duplicate.process(f"Rule matched {protocol} {rule_hash}"):
        stats.log_alert("Rule Based")
        save_alert_to_db(alert_message)
    print(Fore.RED + alert_message + Style.RESET_ALL)

# MAC Flooding
mac_seen = defaultdict(lambda: deque())  # src_ip -> deque of (mac, timestamp)

# ICMP Smurf Attack Detection
icmp_broadcast_tracker = deque()  # list of (timestamp, src_ip)

# IP Fragmentation Attack Detection
fragment_count = defaultdict(deque)  # {src_ip: deque of timestamps}

# TCP RST Flood Detection
rst_packet_count = defaultdict(deque)

# UDP Flood Detection
udp_packet_log = defaultdict(deque)

# DNS Tunneling Detection
dns_query_counts = defaultdict(int)
dns_last_seen = {}

# ARP Spoofing
arp_table = {}  # ip -> mac

# Large ICMP Packet Flood
icmp_alert_times = deque(maxlen=100)

# SYN Scan Detection
syn_count = Counter()
start_time = time.time()

# Live Packet Display Rate Limiting
last_sent_time = time.time()
packet_count = 0
live_packet_queue = Queue()

# (DoS Detection)
packet_rate_map = defaultdict(deque)

# TCP Port Scan Detection
tcp_scan_log = defaultdict(deque)  # (src_ip, dst_ip) -> deque of (port, timestamp)

# Packet storage (for further processing or export)
packet_data = []
packets_buffer=[]

def process_packet(packet):
    attribute=extract_attributes(packet)
    if attribute:
        hashs = attribute.get("hash_strings")
        if attribute.get("protocol")=="tcp":
            for hash in hashs:
                if rule.get("tcp", {}).get(hash):
                    # print(f"[rule matched : tcp ]{hash}")
                    handle_rule_match("tcp", hash, rule.get("tcp", {}).get(hash)+f"Source:{attribute.get('src_ip')},Destination:{attribute.get('dest_ip')}")
                    break
        elif attribute.get("protocol") == "udp":
            for hash in hashs:
                if rule.get("udp", {}).get(hash):
                    # print(f"[rule matched : udp ]{hash}")
                    handle_rule_match("udp", hash, rule.get("udp", {}).get(hash)+f"Source:{attribute.get('src_ip')},Destination:{attribute.get('dest_ip')}")
                    break

        # print(attribute.get("hash_strings"))
    global start_time, last_sent_time, packet_count
    # print(malicious_ips)
    try:

        if packet.haslayer(IP):
            try:
                current_time = time.time()
                if current_time - last_sent_time >= 1:
                    last_sent_time = current_time
                    packet_count = 0

                if packet_count < config["MAX_PACKETS_PER_SECOND"]:
                    pkt_size = len(packet)

                    # Fix: Get class names of layers
                    layer_names = [layer.__name__ for layer in packet.layers()]
                    proto = layer_names[-1] if layer_names else "UNKNOWN"
                    packet_summary={
                                    "src": packet[IP].src,
                                   "dst": packet[IP].dst,
                                   "protocol": proto,
                                   "Size": pkt_size,
                                   "summary":packet.summary(),
                                    }
                    live_packet_queue.put(packet_summary)
                    packets_buffer.append(packet)
                    if len(packets_buffer) >= 20:
                        wrpcap("capture.pcap", packets_buffer, append=True)
                        packets_buffer.clear()
                    packet_count += 1

            except Exception as e:
                print(f"[WARNING] Packet skipped: {e}")
                print("\n========== TRACEBACK ==========")
                traceback.print_exc()
                print("================================\n")

        # SYN Scan Detection
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN
            src_ip = packet[IP].src
            syn_count[src_ip] += 1
            stats.log_packet("TCP")

            if time.time() - start_time > config["TIME_WINDOW"]:
                for ip, count in syn_count.items():
                    if count > config["SYN_THRESHOLD"]:
                        sec=config["TIME_WINDOW"]
                        msg = f"[ALERT] Possible SYN scan from {ip} ({count} SYNs in {sec}s)"
                        if check_duplicate.process(f"SYN Scan attack from {ip}"):
                            stats.log_alert("SYN Scan")
                            save_alert_to_db(msg)
                        print(Fore.RED + msg + Style.RESET_ALL)

                syn_count.clear()
                start_time = time.time()

        #large icmp packet alert
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            pkt_size = len(packet)
            stats.log_packet("TCP")

            if pkt_size > config["ICMP_LARGE_THRESHOLD"]:
                current_time = time.time()
                icmp_alert_times.append(current_time)

                # Remove timestamps older than 5 seconds
                while icmp_alert_times and current_time - icmp_alert_times[0] > config["ICMP_ALERT_WINDOW"]:
                    icmp_alert_times.popleft()

                if len(icmp_alert_times) > config["ICMP_ALERT_LIMIT"]:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    msg = f"[ALERT] ICMP Flood? More than { config['ICMP_ALERT_LIMIT'] } large ICMP packets in {['ICMP_ALERT_WINDOW']}s. Latest from {src_ip} to {dst_ip} ({pkt_size} bytes)"
                    if check_duplicate.process(f"Large ICMP Packet attack from {src_ip}"):
                        stats.log_alert("Large ICMP Packet")
                        save_alert_to_db(msg)

                    print(Fore.RED + msg + Style.RESET_ALL)

                    icmp_alert_times.clear()
         # Large ICMPv6 Packet
        if packet.haslayer(ICMPv6EchoRequest) and packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            pkt_size = len(packet)
            if pkt_size > config['ICMP_LARGE_THRESHOLD']:
                msg = f"[ALERT] Large ICMPv6 packet from {src_ip} to {dst_ip} ({pkt_size} bytes)"
                if check_duplicate.process(f"Large ICMPv6 Packet attack from {src_ip}"):
                    stats.log_alert("Large ICMP Packet")
                    save_alert_to_db(msg)
                print(Fore.RED + msg + Style.RESET_ALL)

        # General Packet Info and Large Packet Anomaly
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            pkt_size = len(packet)

            stats.log_packet("IP")

            packet_data.append({
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Protocol": proto,
                "Packet Size": pkt_size
            })

        # Malicious IP Detection
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            malicious_ips=save_malicious_ips_to_file()
            if src_ip in malicious_ips.keys():
                msg = f"[ALERT] Malicious source IP: {src_ip} ({malicious_ips[src_ip]})"
                if check_duplicate.process(f"Malicious source IP: {src_ip} ({malicious_ips[src_ip]}"):
                    stats.log_alert("Malicious IP")
                    save_alert_to_db(msg)
                print(Fore.RED + msg + Style.RESET_ALL)

            if dst_ip in malicious_ips:
                msg = f"[ALERT] Malicious destination IP: {dst_ip} ({malicious_ips[dst_ip]})"
                if check_duplicate.process(f"Malicious destination IP: {dst_ip} ({malicious_ips[src_ip]}"):
                    stats.log_alert("Malicious IP")
                    save_alert_to_db(msg)
                print(Fore.RED + msg + Style.RESET_ALL)

        # DNS Tunneling Detection
        if packet.haslayer(DNSQR) and packet.haslayer(UDP) and packet[UDP].dport == 53:
            domain = packet[DNSQR].qname.decode(errors='ignore').strip('.')
            labels = domain.split('.')
            stats.log_packet("DNS")

            # Rule 1: Check for long subdomains (base64-like strings)
            long_label = any(len(label) > 50 for label in labels)

            # Rule 2: Track how often this domain is queried
            current_time = time.time()
            if domain not in dns_last_seen:
                dns_last_seen[domain] = current_time
                dns_query_counts[domain] = 1
            else:
                if current_time - dns_last_seen[domain] < config['TIME_WINDOW_DNS']:
                    dns_query_counts[domain] += 1
                else:
                    dns_query_counts[domain] = 1
                    dns_last_seen[domain] = current_time

            # Rule 3: Query rate too high in short time
            if dns_query_counts[domain] > config['QUERY_RATE_THRESHOLD'] or long_label:
                msg = f"[ALERT] Possible DNS tunneling detected: {domain} | Count: {dns_query_counts[domain]}"

                if check_duplicate.process(f"Possible DNS tunneling detected: {domain}"):
                    stats.log_alert("DNS tunneling")
                    save_alert_to_db(msg)
                print(Fore.RED + msg + Style.RESET_ALL)


        # ARP Spoofing Detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc

            stats.log_packet("ARP")
            if src_ip in arp_table:
                # MAC mismatch? Possible spoofing
                if arp_table[src_ip] != src_mac:
                    msg = f"[ALERT] ARP spoofing detected! IP {src_ip} is now claiming MAC {src_mac} (was {arp_table[src_ip]})"
                    if check_duplicate.process(f"ARP spoofing detected! IP {src_ip}"):
                        save_alert_to_db(msg)
                        stats.log_alert("ARP spoofing")
                    print(Fore.RED + msg + Style.RESET_ALL)
            else:
                arp_table[src_ip] = src_mac

        # UDP Flood Detection
        if packet.haslayer(UDP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            now = time.time()

            stats.log_packet("UDP")

            udp_packet_log[src_ip].append(now)

            # Remove old entries outside the time window
            while udp_packet_log[src_ip] and now - udp_packet_log[src_ip][0] > config['UDP_TIME_WINDOW']:
                udp_packet_log[src_ip].popleft()

            # Check if flood threshold exceeded
            if len(udp_packet_log[src_ip]) > config['UDP_THRESHOLD']:
                msg = f"[ALERT] UDP Flood/Port Scan detected from {src_ip}: {len(udp_packet_log[src_ip])} packets in {config['UDP_TIME_WINDOW']} seconds"
                if check_duplicate.process(f"UDP Flood detected from {src_ip}"):
                    save_alert_to_db(msg)
                    stats.log_alert("UDP Flood")
                print(Fore.RED + msg + Style.RESET_ALL)
                udp_packet_log[src_ip].clear()

        # Packet Rate Monitoring (DoS Detection)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            current_time = time.time()

            # Add current timestamp
            packet_rate_map[src_ip].append(current_time)

            # Remove old timestamps outside the rate window
            while packet_rate_map[src_ip] and current_time - packet_rate_map[src_ip][0] > config['RATE_TIME_WINDOW_DOS']:
                packet_rate_map[src_ip].popleft()

            # Check if rate exceeds threshold
            if len(packet_rate_map[src_ip]) > config['PACKET_RATE_THRESHOLD_DOS']:
                msg = f"[ALERT] DoS Suspected: High packet rate from {src_ip} - {len(packet_rate_map[src_ip])} packets in {config['RATE_TIME_WINDOW_DOS']}s"
                if check_duplicate.process(f"DoS Suspected from {src_ip}"):
                    save_alert_to_db(msg)
                    stats.log_alert("DoS")
                print(Fore.RED + msg + Style.RESET_ALL)
                packet_rate_map[src_ip].clear()  #  avoid repeated alerts

        # TCP Reset Flood Detection
        if packet.haslayer(IP) and packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 0x04:  # RST flag (0x04)
                src_ip = packet[IP].src
                current_time = time.time()

                rst_packet_count[src_ip].append(current_time)

                # Remove timestamps older than the time window
                while rst_packet_count[src_ip] and current_time - rst_packet_count[src_ip][0] > ['RST_WINDOW_SECONDS']:
                    rst_packet_count[src_ip].popleft()

                # Check if count exceeds threshold
                if len(rst_packet_count[src_ip]) > config['RST_FLOOD_THRESHOLD']:
                    msg = f"[ALERT] TCP RST Flood suspected from {src_ip} - {len(rst_packet_count[src_ip])} RSTs in {['RST_WINDOW_SECONDS']}s"
                    if check_duplicate.process(f"TCP RST Flood suspected from {src_ip}"):
                        save_alert_to_db(msg)
                        stats.log_alert("TCP RST Flood")
                    print(Fore.RED + msg + Style.RESET_ALL)
                    rst_packet_count[src_ip].clear()  # Avoid repeating the alert constantly

        # IP Fragmentation Attack Detection
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            if ip_layer.flags == 1 or ip_layer.frag > 0:
                src_ip = ip_layer.src
                current_time = time.time()

                fragment_count[src_ip].append(current_time)

                # Remove old timestamps outside the window
                while fragment_count[src_ip] and current_time - fragment_count[src_ip][0] > ['FRAG_WINDOW']:
                    fragment_count[src_ip].popleft()

                if len(fragment_count[src_ip]) > config['FRAG_THRESHOLD']:
                    msg = f"[ALERT] Possible IP Fragmentation attack from {src_ip} - {len(fragment_count[src_ip])} fragments in {['FRAG_WINDOW']}s"
                    if check_duplicate.process(f"IP Fragmentation attack from {src_ip}"):
                        save_alert_to_db(msg)
                        stats.log_alert("IP Fragmentation")
                    print(Fore.RED + msg + Style.RESET_ALL)
                    fragment_count[src_ip].clear()

        # Smurf Attack Detection
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            stats.log_packet("ICMP")
            # ICMP Echo Request (ping)
            if icmp_layer.type == 8:
                dst_ip = ip_layer.dst
                src_ip = ip_layer.src
                current_time = time.time()

                # Check for broadcast pattern (e.g., ends with .255 or .0)
                if dst_ip.endswith('.255') or dst_ip.endswith('.0'):
                    icmp_broadcast_tracker.append((current_time, src_ip))

                    # Remove old entries
                    while icmp_broadcast_tracker and current_time - icmp_broadcast_tracker[0][0] > config['ICMP_SMURF_WINDOW']:
                        icmp_broadcast_tracker.popleft()

                    # Count how many pings went to broadcast recently
                    if len(icmp_broadcast_tracker) > config['ICMP_SMURF_THRESHOLD']:
                        msg = f"[ALERT] Possible Smurf Attack: {len(icmp_broadcast_tracker)} ICMP Echo Requests to broadcast addresses in {config['ICMP_SMURF_WINDOW']}s. Latest from {src_ip}"
                        if check_duplicate.process(f"Smurf Attack from {src_ip}"):
                            save_alert_to_db(msg)
                            stats.log_alert("Smurf Attack")
                        print(Fore.RED + msg + Style.RESET_ALL)
                        icmp_broadcast_tracker.clear()

        # Land Attack Detection
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            if ip_layer.src == ip_layer.dst and tcp_layer.sport == tcp_layer.dport:
                msg = f"[ALERT] Land Attack detected: Source and Destination IP/Port are the same ({ip_layer.src}:{tcp_layer.sport})"
                if check_duplicate.process(f"Land Attack detected {ip_layer.src}"):
                    save_alert_to_db(msg)
                    stats.log_alert("Land Attack")
                print(Fore.RED + msg + Style.RESET_ALL)

        # MAC Flooding Detection
        if packet.haslayer(Ether) and packet.haslayer(IP):
            src_mac = packet[Ether].src
            src_ip = packet[IP].src
            now = time.time()

            # Record new MAC usage for this IP
            mac_queue = mac_seen[src_ip]
            mac_queue.append((src_mac, now))

            # Remove MACs outside the time window
            while mac_queue and now - mac_queue[0][1] > config['MAC_FLOOD_WINDOW']:
                mac_queue.popleft()

            # Count unique MACs in the window
            unique_macs = set(mac for mac, _ in mac_queue)

            if len(unique_macs) > config['MAC_FLOOD_THRESHOLD']:
                msg = f"[ALERT] MAC Flooding attack suspected from {src_ip}: {len(unique_macs)} unique MACs in {['MAC_FLOOD_WINDOW']}s"
                if check_duplicate.process(f"MAC Flooding attack suspected from {src_ip}"):
                    save_alert_to_db(msg)
                    stats.log_alert("MAC Flooding")
                print(Fore.RED + msg + Style.RESET_ALL)
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
                while tcp_scan_log[key] and now - tcp_scan_log[key][0][1] > config['TCP_SCAN_WINDOW']:
                    tcp_scan_log[key].popleft()

                # Count unique destination ports
                unique_ports = {port for port, _ in tcp_scan_log[key]}
                if len(unique_ports) > config['TCP_SCAN_THRESHOLD']:
                    msg = f"[ALERT] TCP Port Scan detected from {ip.src} to {ip.dst} on ports: {sorted(unique_ports)}"
                    if check_duplicate.process(f"TCP Port Scan detected from {ip.src}"):
                        save_alert_to_db(msg)
                        stats.log_alert("TCP Port Scan")
                    print(Fore.RED + msg + Style.RESET_ALL)

                    tcp_scan_log[key].clear()  # Optional: Reset after detection


    except Exception as e:
        print(Fore.YELLOW + f"[WARNING] Packet skipped: {e}" + Style.RESET_ALL)
        # print("\n========== TRACEBACK ==========")
        # traceback.print_exc()
        # print("================================\n")


def start_sniffing(interface):
    print(f"[*] Sniffing started on: {interface}")
    sniff(iface=interface, prn=process_packet, store=0,filter="ip")

