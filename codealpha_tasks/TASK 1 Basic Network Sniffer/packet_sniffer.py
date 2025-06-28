from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print("\n📦 New Packet Captured!")
        print(f"🔹 From: {ip_layer.src}")
        print(f"🔸 To:   {ip_layer.dst}")
        
        if TCP in packet:
            print("🧭 Protocol: TCP")
            print(f"Port: {packet[TCP].sport} ➡ {packet[TCP].dport}")
        elif UDP in packet:
            print("🧭 Protocol: UDP")
            print(f"Port: {packet[UDP].sport} ➡ {packet[UDP].dport}")
        elif ICMP in packet:
            print("🧭 Protocol: ICMP")
        else:
            print("🧭 Protocol: Other")

        if Raw in packet:
            print(f"📄 Payload: {packet[Raw].load[:50]}")

print("🚀 Starting Packet Sniffer... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)
