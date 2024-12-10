from scapy.all import *

def receive_packets(packet):
    if packet.haslayer(IP):
        if packet.haslayer(Raw):
            print(f"Pacote recebido de {packet[IP].src} para {packet[IP].dst}")
            print(f"Payload: {packet[Raw].load.decode(errors='ignore')}")

def start_receiver(iface):
    try:
        print(f"Iniciando o sniffing na interface {iface} para receber pacotes...")
        sniff(prn=receive_packets, iface=iface, filter="ip", store=False)
    except Exception as e:
        print(f"Erro ao iniciar o sniffing: {e}")

if __name__ == "__main__":
    iface = 'h1-eth0'
    start_receiver(iface)
