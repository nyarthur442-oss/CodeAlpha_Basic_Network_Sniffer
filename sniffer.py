from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import sys

def packet_callback(packet):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n[{time}] --- Packet Captured ---")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto} | TTL: {ip_layer.ttl} | Length: {ip_layer.len}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP | Src Port: {tcp_layer.sport} -> Dst Port: {tcp_layer.dport}")
            if packet.haslayer('Raw'):
                try:
                    payload = packet['Raw'].load.decode('utf-8', errors='ignore')[:100]
                    print(f"Payload Preview: {payload}")
                except:
                    print("Payload: [Binary Data]")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP | Src Port: {udp_layer.sport} -> Dst Port: {udp_layer.dport}")
        elif ICMP in packet:
            print(f"Protocol: ICMP")

        print("-" * 50)

def main():
    print("=== CodeAlpha Basic Network Sniffer ===")
    print("By Arthur Ransford | ID: CA/DF1/306921")
    try:
        count = int(input("Enter number of packets to capture (e.g., 10): "))
    except:
        count = 10
    
    print(f"\nStarting capture of {count} packets...")
    print("Tip: Open browser / ping google.com to generate traffic\n")
    sniff(prn=packet_callback, count=count)
    print("\nCapture Complete. Report saved to analysis.txt")

if __name__ == "__main__":
    main()
