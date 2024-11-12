from scapy.all import *
import time
import threading
import subprocess
import ipaddress

# Definição dos pacotes BBLP
class BBLP_TABLE_LINE(Packet):
    name = "BBLP_TABLE_LINE"
    fields_desc = [
        IPField("destination", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("nexthop", "0.0.0.0"),
        StrFixedLenField("interface", "eth0", length=10),
        IntField("weight", 1)
    ]

class BBLP(Packet):
    name = "BBLP"
    fields_desc = [
        IPField("origin", "0.0.0.0"),
        IntField("routeCount", 0)
    ]

    def add_route(self, destination, mask, nexthop, interface, weight):
        route_entry = BBLP_TABLE_LINE(destination=destination, mask=mask, nexthop=nexthop, interface=interface, weight=weight)
        self.add_payload(route_entry)
        self.routeCount += 1

    def extract_routes(self):
        routes = []
        payload = self.payload
        while payload and isinstance(payload, BBLP_TABLE_LINE):
            routes.append((payload.destination, payload.mask, payload.nexthop, payload.interface, payload.weight))
            payload = payload.payload
        return routes

# Variável global para armazenar as rotas
TableRoute = {}

bind_layers(BBLP, BBLP_TABLE_LINE)

def get_network_ip(ip_address, subnet_mask):
    """
    Função para calcular o IP da rede dada o IP e a máscara de sub-rede.
    """
    network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
    return str(network.network_address)
    
def get_nexthop_for_interface(interface):
    """
    Função para obter o IP do nexthop (próximo dispositivo) para uma interface específica.
    Isso pode ser obtido da tabela de rotas do sistema.
    """
    # Executa o comando 'ip route' para obter as rotas
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    
    # Percorre cada linha da saída da tabela de rotas
    for line in output.splitlines():
        parts = line.strip().split()
        
        # Verifica se a linha contém a interface e nexthop
        if 'dev' in parts and parts[-2] == interface:
            nexthop = parts[2]  # O nexthop é o IP após 'via'
            return nexthop
    
    # Se não encontrar um nexthop, retorna um valor padrão (pode ser alterado conforme necessário)
    return "0.0.0.0"

def get_interfaces_and_ips():
    """
    Função para obter as interfaces de rede e suas informações, incluindo nexthop.
    """
    global TableRoute  # Usando a variável global TableRoute
    # Executa o comando 'ip addr show' para obter informações de rede
    output = subprocess.check_output(['ip', 'addr', 'show'], universal_newlines=True)
    
    # Dicionário para armazenar as interfaces com os detalhes
    TableRoute = {}

    # Processa cada linha da saída do comando 'ip addr show'
    for line in output.splitlines():
        # Verifica se a linha contém a informação do endereço IP
        if "inet " in line:
            ip_info = line.strip().split()  # Divide a linha em uma lista de elementos
            ip_address = ip_info[1]  # O endereço IP com a máscara, ex: 192.168.1.100/24
            iface = ip_info[-1]  # O nome da interface é o último elemento da linha
            
            # Imprime as informações de depuração
            print(f"ip_info: {ip_info}, ip_address: {ip_address}, iface: {iface}")

            # Ignora a interface de loopback 'lo'
            if iface and iface != 'lo':
                # Divide o IP e a máscara usando '/'
                network, mask = ip_address.split('/')
                
                # Calcular o IP da rede usando a função
                network_ip = get_network_ip(network, mask)
                
                # Aqui, assumimos que o nexthop será o primeiro dispositivo na tabela de rotas do sistema
                nexthop = get_nexthop_for_interface(iface)  # Função a ser implementada

                # Adiciona as informações da interface ao dicionário
                TableRoute[network_ip] = {
                    'nexthop': nexthop,  # IP do próximo roteador (nexthop)
                    'mask': mask,        # Máscara da rede
                    'interface': iface,  # Nome da interface
                    'weight': 0          # Peso da rota
                }
    
    # Imprime as rotas para depuração
    print(TableRoute)
    # Retorna o dicionário com as interfaces e seus detalhes
    return TableRoute


# Função para capturar pacotes e trocar rotas
def receive_routes(pkt):
    if pkt.haslayer(BBLP):
        print("RECEBI PACOTE BBLP")
        bblp_pkt = pkt.getlayer(BBLP)
        print(f"Recebido pacote BBLP de {pkt[IP].src}")

        # Processa rotas
        routes = bblp_pkt.extract_routes()
        for route in routes:
            print(f"Rota recebida: {route}")

# Função de anúncio de rotas
def announce_routes(node_ip, interface):
    while True:
        print(f"Anunciando rotas de {node_ip} na interface {interface}")

        # Cria o pacote BBLP com a origem e contador de rotas inicializado
        bblp_pkt = BBLP(origin=node_ip, routeCount=0)

        # Adiciona cada entrada de TableRoute ao pacote BBLP
        for network_ip, route_info in TableRoute.items():
            # Para cada rota na tabela, adiciona ao pacote como um BBLP_TABLE_LINE
            bblp_pkt.add_route(
                destination=network_ip,
                mask=route_info['mask'],
                nexthop=route_info['nexthop'],
                interface=route_info['interface'],
                weight=route_info['weight']
            )

        # Envia o pacote BBLP para a rede via broadcast
        ip_packet = IP(dst="255.255.255.255") / UDP(dport=12345) / bblp_pkt
        send(ip_packet, iface=interface)
        print(f"Rota de {node_ip} anunciada para {interface}")
        
        time.sleep(5)  # Envia a cada 5 segundos


def start_router(node_ip, interface):
    print(f"Iniciando roteador para {node_ip} na interface {interface}")
    
    threading.Thread(target=announce_routes, args=(node_ip, interface), daemon=True).start()

    threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': receive_routes}, daemon=True).start()



# Chame esta função para iniciar o roteador
def run_router():

    interfaces = get_interfaces_and_ips()  # Pega as interfaces e IPs do roteador
    print("")
    print(f"Interfaces encontradas: {interfaces}")
    print("")
    
    # Para cada interface, inicie a troca de rotas
    for network, info in interfaces.items():  # Agora estamos percorrendo as chaves 'network' e os valores 'info'
        node_ip = info['nexthop']  # O IP do próximo dispositivo (nexthop)
        iface = info['interface']  # O nome da interface
        print(f"Iniciando roteador na interface {iface} com nexthop {node_ip}")
        start_router(node_ip, iface)  # Chama a função start_router passando o nexthop e a interface
    
    print("Esperando rotas...")

    while True:
        time.sleep(1)  # Simples loop para manter o script rodando

# Inicie o roteador
run_router()

