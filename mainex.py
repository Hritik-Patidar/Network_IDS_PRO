from app import pack_cap as p
import pandas as pd

# Ask user for packet count
if __name__ == "__main__":
    packet_count = int(input("Enter the number of packets to capture: "))
    # Start capturing packets
    print(f"Starting packet capture for {packet_count} packets...")
    p.sniff(iface=p.interfaces, prn=p.process_packet, count=packet_count, store=False)
    # Convert captured data to a DataFrame
    df = pd.DataFrame(p.packet_data)
    print("\nCaptured Packet Summary:")
    print(df.head())

    # Analyze packet distribution
    print("\nTop 10 Source IPs:")
    print(p.Counter(df["Source IP"]).most_common(10))