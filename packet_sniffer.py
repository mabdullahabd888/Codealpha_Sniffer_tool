from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    print("\n=== Packet Captured ===")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"[IP] {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[TCP] Port {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[UDP] Port {udp_layer.sport} -> {udp_layer.dport}")

        elif ICMP in packet:
            print("[ICMP] Packet")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload: {payload[:100]}")
    else:
        print("Non-IP Packet")

def start_sniffing(interface=None, packet_count=5):
    print(f"Sniffing on interface: {interface or 'default'}")
    sniff(iface=interface, prn=analyze_packet, count=packet_count, store=False)

if __name__ == "__main__":
    start_sniffing(interface=None, packet_count=5)
