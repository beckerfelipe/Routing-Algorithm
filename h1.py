from scapy.all import sniff, TCP

def process_packet(packet):
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print(f"\n[+] Pacote TCP capturado:")
        print(f"  Porta de origem: {tcp_layer.sport}")
        print(f"  Porta de destino: {tcp_layer.dport}")
        print(f"  Flags: {tcp_layer.flags}")
        if tcp_layer.payload:
            print(f"  Payload: {bytes(tcp_layer.payload)}")

print("Sniffando pacotes TCP...")
sniff(filter="tcp", prn=process_packet, count=10)