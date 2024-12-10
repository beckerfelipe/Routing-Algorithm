from scapy.all import *
from brainword import *
import chardet  # Para detectar a codificação do texto

modified = 0
received = 0

def receive_pepekets(packet):
    global modified
    global received

    if packet.haslayer(IP): 
        if packet.haslayer(Raw): 
            received += 1
            raw_data = packet[Raw].load

            encoding = detect_encoding(raw_data)

            try:
                original_payload = raw_data.decode(encoding, errors="ignore")
            except Exception as e:
                print(f"Erro ao decodificar o payload: {e}")
                return 

            modified_payload = filter_brainrot_content(packet)

            if modified_payload == original_payload:
                print(f"Pacote com conteúdo 'brainrot' detectado e modificado: {modified_payload}")
                modified += 1

            packet[Raw].load = modified_payload.encode(encoding, errors="ignore")

            print(f"Pacote modificado e pronto para envio: {modified_payload}")

            ip_packet = IP(src=packet[IP].src, dst="10.1.1.1") / packet[Raw]

            if packet.haslayer(TCP):
                ip_packet /= packet[TCP]

            send(ip_packet)

        print(f"Modificados: {modified}")
        print(f"Recebidos: {received}")
        print(f"Taxa de drop: {modified / received if received > 0 else 0:.2f}")

def start_router(iface):
    try:
        print(f"Iniciando sniffing na interface {iface}...")
        sniff(prn=receive_pepekets, iface=iface, filter="ip", store=False)
    except Exception as e:
        print(f"Erro no start_router: {e}")

if __name__ == "__main__":
    iface = 'r-eth2'
    start_router(iface)
