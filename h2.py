import threading
import time
import random
from scapy.all import IP, TCP, Raw, send

# Mensagens a serem enviadas
messages = [
    "C0nh3c4 os beneficio$ do M3wing",
    "Beneficios do aprendizado continuo",
    "A rede esta funcionando corretamente",
    "M3wing! Mensagem do servidor",
]

# Criação de um pacote TCP com mensagem aleatória
def create_packet():
    message = random.choice(messages)
    packet = IP(dst="10.1.1.254") / TCP(dport=80) / Raw(load=message)
    return packet

# Envia pacotes continuamente
def send_packet():
    while True:
        packet = create_packet()
        print(f"h2 ENVIOU PACOTE: {packet[Raw].load.decode()}")
        send(packet)
        time.sleep(1)  # Pausa de 1 segundo entre os envios

if __name__ == "__main__":
    # Executa o envio de pacotes em uma thread separada
    threading.Thread(target=send_packet, daemon=True).start()

    # Mantém o programa em execução
    while True:
        time.sleep(1)
