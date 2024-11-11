from scapy.all import *
import threading
import time

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

# Classe para o Roteador
class Router:
    def __init__(self, node, network_info):
        self.node = node
        self.ip = node.IP()  # IP do nó (o roteador)
        self.table = {}  # Tabela de rotas

        # Inicializar tabela de rotas com as redes diretamente conectadas
        for intf_name, info in network_info.items():
            self.table[info['network']] = {
                "mask": "255.255.255.0", 
                "nexthop": info['destination'], 
                "interface": intf_name, 
                "weight": 1
            }

        print(f"Tabela de Rotas Inicial para {self.ip}: {self.table}")

    def send_routes(self):
        packet = BBLP(origin=self.ip, routeCount=0)

        # Adiciona as rotas ao pacote BBLP
        for destination, data in self.table.items():
            packet.add_route(destination, data['mask'], data['nexthop'], data['interface'], data['weight'])

        # Envia o pacote para todos os destinos (de acordo com as interfaces de saída)
        for destination, data in self.table.items():
            out_iface = data['interface']
            if out_iface:
                try:
                    ip_packet = IP(dst=destination) / packet  # Empacota o pacote BBLP dentro de um pacote IP
                    send(ip_packet, iface=out_iface)  # Envia o pacote IP encapsulando o BBLP
                except Exception as e:
                    print(f"Erro ao enviar pacote para {destination} pela interface {out_iface}: {e}")
            else:
                print(f"Interface de saída para {destination} não encontrada!")

    def receive_routes(self, pkt):
        # Função que processa os pacotes BBLP recebidos
        if pkt.haslayer(BBLP):
            bblp_pkt = pkt.getlayer(BBLP)
            print(f"Recebido pacote BBLP de {pkt[IP].src}")

            # Extraindo rotas do pacote BBLP
            routes = bblp_pkt.extract_routes()
            for route in routes:
                destination, mask, nexthop, interface, weight = route
                print(f"Rota recebida: {destination} / {mask}, nexthop: {nexthop}, interface: {interface}, peso: {weight}")

                # Atualiza a tabela de rotas do roteador com as rotas recebidas
                self.table[destination] = {
                    'mask': mask, 'nexthop': nexthop, 'interface': interface, 'weight': weight
                }

    def announce_routes(self):
        while True:
            print(f"Anunciando tabela de rotas para {self.ip}")
            self.send_routes()
            time.sleep(100)  # Envia a cada 100 segundos

    def start(self):
        # Cria o thread para anunciar rotas
        thread = threading.Thread(target=self.announce_routes)
        thread.daemon = True
        thread.start()

        # Inicia a captura de pacotes
        iface = self.node.defaultIntf().name  # Interface padrão
        available_interfaces = [intf.name for intf in self.node.intfList()]

        if iface in available_interfaces:
            try:
                sniff(iface=iface, prn=self.receive_routes)  # Captura pacotes
            except Exception as e:
                print(f"Erro ao capturar pacotes na interface {iface}: {e}")
