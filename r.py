from scapy.all import sniff, IP, TCP, Raw, send
from brainword import *

dropped = 0
received = 0

def receive_pepekets(packet):
    global dropped  
    global received  

    if packet.haslayer(TCP):
        received += 1
        if packet.haslayer(Raw):
            packet[Raw].load = filter_brainrot_content(packet).encode()
            dropped += 1
        
        print(f"dropados: {dropped}")
        print(f"receba siuuu melhor do mundo: {received}")
        print(f"Taxa de drop: {dropped / received if received > 0 else 0:.2f}")
        
        ip_packet = IP(dst="10.1.1.254/24") / packet[TCP] / packet[Raw]
        send(ip_packet)

def start_router(iface):
    try:
        print(f"Iniciando sniffing na interface {iface}...")
        sniff(prn=receive_pepekets, iface=iface, filter="ip", store=False)
    except Exception as e:
        print(f"Erro no start_router: {e}")

if __name__ == "__main__":
    iface = 'r-eth2'  # Replace with the correct network interface
    start_router(iface)