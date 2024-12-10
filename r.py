from scapy.all import sniff, IP, TCP
from brainword import *

def receive_pepekets(packet):
    if packet.haslayer(TCP):
        print(f"Pacote recebido de {packet.src}")
        if packet.haslayer(Raw):
            packet[Raw].load = filter_brainrot_content(packet).encode()
        
        ip_packet = IP(dst="10.1.1.254/24") / packet[TCP] / packet[Raw]
        send(ip_packet)

def start_router(iface):
    try:
        print(f"Iniciando sniffing na interface {iface}...")
        sniff(prn=receive_pepekets, iface=iface, filter="ip", store=False)
    except Exception as e:
        print(f"Erro no start_router: {e}")

if __name__ == "__main__":
    iface = 'r-eth2'
    start_router(iface)