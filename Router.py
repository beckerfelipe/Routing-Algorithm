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
        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(tableLine.network,tableLine.interface, tableLine.nextRouter, tableLine.weight))

    def PrintGraph(self):
        for node in self.graph:
            print(node)
            for line in self.graph[node]:
                print(line.network, line.interface, line.nextRouter, line.weight)

    def UpdateNode(self, routerTable):
        if routerTable.name not in self.graph:
            self.graph[routerTable.name] = []

        self.graph[routerTable.name].clear()

        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(tableLine.network,tableLine.interface, tableLine.nextRouter, tableLine.weight))

    def Dijkstra(self):#retorna a tabela de rotas dessa roteador baseado no grafo da rede
        start_router=self.routerName
        distances = {start_router: 0}
        previous_nodes = {start_router: None}
        priority_queue = [(0, start_router)] 

        while priority_queue:
            current_distance, current_router = heapq.heappop(priority_queue)

            if current_distance > distances.get(current_router, float('inf')):
                continue

            for line in self.graph.get(current_router,[]):
                weight=line.weight
                nextHop=line.nextRouter
                distance = current_distance + weight
                if distance < distances.get(nextHop, float('inf')):
                    distances[nextHop] = distance
                    previous_nodes[nextHop] = current_router
                    heapq.heappush(priority_queue, (distance, nextHop))

        new_router_table = RouterTable(start_router)
        for router, distance in distances.items():
            if router != start_router:
                next_hop = router
                while previous_nodes[next_hop] != start_router:
                    next_hop = previous_nodes[next_hop]
                print(start_router,next_hop)
                new_router_table.addRoute(TableLine(NetWork.get(router),Interfaces.get((start_router,next_hop)),next_hop,distance))
        print(distances)
        return new_router_table

class BBLP_TABLE_LINE(Packet):
    name = "BBLP_TABLE_LINE"
    fields_desc = [
        StrFixedLenField("destinationNetwork", "2255.255.255.255", length=15),
        StrFixedLenField("nextRouter", "Router", length=10),
        StrFixedLenField("interface", "eth0", length=10),
        IntField("weight", 1)
    ]

class BBLP(Packet):
    name = "BBLP"
    fields_desc = [
        StrFixedLenField("routerName", "Router", length=10),
        IntField("routeCount", 0)
    ]

    def __init__(self, originName):
        Packet.__init__(self)
        self.routerName=originName
        self.routeCount=0

    def add_route(self, destinationNetwork, nextRouter, interface, weight):
        route_entry = BBLP_TABLE_LINE(
            destinationNetwork=destinationNetwork,
            nextRouter=nextRouter,
            interface=interface,
            weight=weight
        )
        self.add_payload(route_entry)
        self.routeCount += 1

    def extract_routes(self): #retorna RouterTable
        routerTable=RouterTable(self.routerName.decode('utf-8').strip())
        payload = self.payload
        while isinstance(payload, BBLP_TABLE_LINE):
            routerTable.addRoute(TableLine(
                payload.destinationNetwork.decode('utf-8').strip(),
                payload.nextRouter.decode('utf-8').strip(),
                payload.interface.decode('utf-8').strip(),
                payload.weight
            ))
            payload = payload.payload  # Move to the next layer

        return routerTable

def receive_routes(pkt):
    pkt.show()
    if pkt.haslayer(BBLP):
        print("RECEBI PACOTE BBLP")
        bblp_pkt = pkt.getlayer(BBLP)
        print(f"Recebido pacote BBLP de {pkt[IP].src}")

        routes = bblp_pkt.extract_routes()
        for route in routes:
            print(f"Rota recebida: {route}")

#TODO quando a topologia estiver correta criar para cada roteador o networkGraph e corrigir esses metodos de enviar e receber rotas
# com isso pronto deve ser possivel cada roteador ficar enviando a sua tabela de rotas e receber a dos outros 
# pra cada tabela recebida atualizar o nó do roteador e calcular dijkstra novamente

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


# A partir daqui é tudo debug e vai ser removido em breve

route1 = TableLine("192.168.1.0","A-B", "RouterB", 1000)
route2 = TableLine("192.168.2.0","B-C", "RouterC", 2000)

routerA = RouterTable("RouterA")
routerB = RouterTable("RouterB")

routerA.addRoute(route1)
routerB.addRoute(route2)


networkGraph = NetworkGraph(routerA)
networkGraph.UpdateNode(routerB)

new_routes = networkGraph.Dijkstra()
for line in new_routes.routeList:
    print(line.network, line.interface, line.nextRouter, line.weight)

networkGraph.PrintGraph()

newLine = routerB.routeList[0]
newLine.weight=3333
routerB.changeLine(routerB.routeList[0],newLine)

print("")

networkGraph.UpdateNode(routerB)

networkGraph.PrintGraph()


new_routes = networkGraph.Dijkstra()
for line in new_routes.routeList:
    print(line.network, line.interface, line.nextRouter, line.weight)

bblp=BBLP(originName="RouterB")
bblp.add_route("0202.2020","RouterD","B-D",123)
bblp.add_route("1222.2525","RouterC","B-C",1000)
bblp.show()

print("")

networkGraph.UpdateNode(bblp.extract_routes())
networkGraph.PrintGraph()

new_routes = networkGraph.Dijkstra()
for line in new_routes.routeList:
    print(line.network, line.interface, line.nextRouter, line.weight)

