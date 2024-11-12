from scapy.all import *
import time
import threading
import subprocess
import ipaddress

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

TableRoute = {}

bind_layers(BBLP, BBLP_TABLE_LINE)

def get_network_ip(ip_address, subnet_mask):

    network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
    return str(network.network_address)
    
def get_nexthop_for_interface(interface):
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    
    for line in output.splitlines():
        parts = line.strip().split()
        
        if 'dev' in parts and parts[-2] == interface:
            nexthop = parts[2]
            return nexthop
    return "0.0.0.0"

def get_interfaces_and_ips():
    global TableRoute
    output = subprocess.check_output(['ip', 'addr', 'show'], universal_newlines=True)
    
    TableRoute = {}

    for line in output.splitlines():
        if "inet " in line:
            ip_info = line.strip().split()
            ip_address = ip_info[1]
            iface = ip_info[-1]  
            
            print(f"ip_info: {ip_info}, ip_address: {ip_address}, iface: {iface}")

            if iface and iface != 'lo':

                network, mask = ip_address.split('/')
                
                network_ip = get_network_ip(network, mask)
                
                nexthop = get_nexthop_for_interface(iface) 


                TableRoute[network_ip] = {
                    'nexthop': nexthop,  # IP do próximo roteador (nexthop)
                    'mask': mask,        # Máscara da rede
                    'interface': iface,  # Nome da interface
                    'weight': 0          # Peso da rota
                }
    

    print(TableRoute)
    return TableRoute



def receive_routes(pkt):
    pkt.show()
    if pkt.haslayer(BBLP):
        print("RECEBI PACOTE BBLP")
        bblp_pkt = pkt.getlayer(BBLP)
        print(f"Recebido pacote BBLP de {pkt[IP].src}")

        routes = bblp_pkt.extract_routes()
        for route in routes:
            print(f"Rota recebida: {route}")


def send_routes(node_ip, interface):
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
        
        time.sleep(15) 


def start_router(node_ip, interface):
    print(f"Iniciando roteador para {node_ip} na interface {interface}")
    
    threading.Thread(target=send_routes, args=(node_ip, interface), daemon=True).start()

    threading.Thread(target=sniff, kwargs={'iface': interface, 'prn': receive_routes}, daemon=True).start()



def run_router():

    interfaces = get_interfaces_and_ips()
    print("")
    print(f"Interfaces encontradas: {interfaces}")
    print("")
    

    for network, info in interfaces.items():  
        node_ip = info['nexthop']  
        iface = info['interface']  
        print(f"Iniciando roteador na interface {iface} com nexthop {node_ip}")
        start_router(node_ip, iface)  

    while True:
        time.sleep(1)  

run_router()

