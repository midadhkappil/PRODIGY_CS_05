from scapy.all import *
from datetime import datetime

protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}

def packet_callback(packet):

    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        packet_size = len(packet)

        protocol_name = protocols.get(protocol, f"Other ({protocol})")

        print(f"Time: {timestamp}")
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}, Packet Size: {packet_size} bytes")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload Data: {payload}\n")
        else:
            print("No Payload Data\n")
    else:
        print("Non-IP Packet Captured\n")

def start_sniffing():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("Packet sniffing stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")
