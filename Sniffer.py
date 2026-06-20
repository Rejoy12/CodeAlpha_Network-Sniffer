from scapy.all import *
from datetime import datetime

protocols = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 60)
    print(f"Packet Number : {packet_count}")
    print(f"Time          : {datetime.now()}")

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto
        proto = protocols.get(proto_num, str(proto_num))

        print(f"Protocol      : {proto}")
        print(f"Source IP     : {src}")
        print(f"Destination IP: {dst}")

    if packet.haslayer(TCP):
        print(f"Source Port   : {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif packet.haslayer(UDP):
        print(f"Source Port   : {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    if packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            print(f"Payload       : {payload[:100]}")
        except:
            pass

print("Starting Network Sniffer...")
sniff(filter="ip", prn=packet_callback, store=False)