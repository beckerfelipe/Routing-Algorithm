import heapq
from scapy.all import *
import time
import threading
import subprocess
import ipaddress

NetWork={'RouterA':'192.168.1.0','RouterB':'192.168.1.0', 'RouterC':'192.168.3.0'}

Interfaces={("RouterA","RouterB"):"A-B", ("RouterB","RouterC"):"B-C"}

class TableLine:
    def __init__(self, network, interface, nextRouter, weight):
        self.network=network #rede de destino
        self.interface=interface #interface que liga com o proximo roteador 
        self.nextRouter=nextRouter
        self.weight=weight
    

class RouterTable:
    def __init__(self, name):
        self.name=name       #nome do host/roteador atual
        self.routeList=[]

    def addRoute(self, tableLine):
        self.routeList.append(tableLine)

    def changeLine(self, old, new):
        index=self.routeList.index(old)
        self.routeList[index]=new


class NetworkGraph:
    def __init__(self, routerTable):
        self.graph = {}
        self.routerName=routerTable.name
        self.graph[self.routerName]=[]
        self.neighbors=[]
        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(tableLine.network,tableLine.interface, tableLine.nextRouter, tableLine.weight))

    def AddNeighbor(self, neighbor):
        self.neighbors.append(neighbor)

    def UpdateNode(self, routerTable):
        if routerTable.name not in self.graph:
            self.graph[routerTable.name] = []

        self.graph[routerTable.name].clear()
        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(tableLine.network,tableLine.interface, tableLine.nextRouter, tableLine.weight))

    def Dijkstra(self):#retorna a tabela de rotas dessa roteador baseado no grafo da rede
         # Dijkstra's Algorithm to find the shortest paths from start_network
        start_router=self.routerName
        distances = {start_router: 0}
        previous_nodes = {start_router: None}
        priority_queue = [(0, start_router)]  # (distance, network)

        while priority_queue:
            current_distance, current_router = heapq.heappop(priority_queue)

            if current_distance > distances.get(current_router, float('inf')):
                continue

            # Update distances for neighbors (next-hop routers)
            for line in self.graph.get(current_router,[]):
                weight=line.weight
                nextHop=line.nextRouter
                distance = current_distance + weight
                if distance < distances.get(nextHop, float('inf')):
                    distances[nextHop] = distance
                    previous_nodes[nextHop] = current_router
                    heapq.heappush(priority_queue, (distance, nextHop))
        # Reconstruct the route table from the distances and previous nodes
        new_router_table = RouterTable(start_router)
        for router, distance in distances.items():
            if router != start_router:
                # Inicia com o roteador anterior calculado pelo Dijkstra
                next_hop = router
                while previous_nodes[next_hop] != start_router:
                    next_hop = previous_nodes[next_hop]
                print(start_router,next_hop)
                new_router_table.addRoute(TableLine(NetWork.get(router),Interfaces.get((start_router,next_hop)),next_hop,distance))

        return new_router_table

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

#run_router()
route1 = TableLine("192.168.1.0","A-B", "RouterB", 1)
route2 = TableLine("192.168.2.0","B-C", "RouterC", 2)

routerA = RouterTable("RouterA")
routerB = RouterTable("RouterB")

routerA.addRoute(route1)
routerB.addRoute(route2)


networkGraph = NetworkGraph(routerA)
networkGraph.UpdateNode(routerB)
networkGraph.AddNeighbor('routerB')

# Run Dijkstra's algorithm from RouterA (192.168.1.0) to find shortest paths
new_routes = networkGraph.Dijkstra()
for line in new_routes.routeList:
    print(line.network, line.interface, line.nextRouter, line.weight)