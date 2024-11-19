import heapq
from scapy.all import *
import time
import threading
import subprocess
import ipaddress

NetWork={'RouterA':'10.1.1.0','RouterB':'10.2.2.0'} # pode ser setado manualmente é igual para todos os roteadores

Interfaces={("RouterA","RouterB"):"r1-eth1", ("RouterB","RouterA"):"r2-eth1",
            ("hostA-RouterA"):"h1-eth0",("RouterA-hostA"):"r1-eth0",
            ("hostB-RouterB"):"h2-eth0",("RouterB-hostB"):"r2-eth0"
            } #pode ser setado manualmente pois é unica para toda a rede

RouterNeighbors={} #vizinhos desse roteador e interface entre eles

networkGraph=None

class TableLine:
    def __init__(self, network, interface, nextRouter, weight):
        self.network=network #rede de destino
        self.interface=interface #interface que liga com o proximo roteador 
        self.nextRouter=nextRouter
        self.weight=weight
    

globalRouteTable={"RouterA":[TableLine("10.2.2.0","r1-eth1","RouterB",2)], "RouterB":[TableLine("10.1.1.0","r2-eth1","RouterA",5)]} #pra cada roteador seu vizinhos

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
        StrFixedLenField("destinationNetwork", "255.255.255.255", length=15),
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

    def __init__(self):
        Packet.__init__(self)
        if networkGraph != None:
        	self.routerName=networkGraph.routerName
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
        
bind_layers(IP,BBLP)

#TODO quando a topologia estiver correta criar para cada roteador o networkGraph e corrigir esses metodos de enviar e receber rotas
# com isso pronto deve ser possivel cada roteador ficar enviando a sua tabela de rotas e receber a dos outros 
# pra cada tabela recebida atualizar o nó do roteador e calcular dijkstra novamente

def send_routes():
    while True:
        try:
            # Validação do nome do roteador antes de criar o pacote
            print(f"Router Name: {networkGraph.routerName}")
            if not networkGraph.routerName:
                raise ValueError("O nome do roteador (routerName) não está definido.")

            # Criação do pacote BBLP com o nome de origem
            bblp_pkt = BBLP()
            
            for line in networkGraph.graph[networkGraph.routerName]:
                bblp_pkt.add_route(
                    destinationNetwork=line.network,
                    nextRouter=line.nextRouter,
                    interface=line.interface,
                    weight=line.weight
                )

            # Envio para vizinhos
            for router in RouterNeighbors:
                ip_packet = IP(dst=NetWork[router]) / bblp_pkt
                send(ip_packet, iface=RouterNeighbors[router])
                print(f"Anunciando rotas de {networkGraph.routerName} para {router} na interface {RouterNeighbors[router]}")

        except Exception as e:
            print(f"Erro no envio de rotas: {e}")
       	time.sleep(15)

def receive_routes(pkt):
    print("RECEBEU ALGO")
    print(f"Pacote recebido: {pkt.summary()}")
    if(pkt.haslayer(BBLP)):
        print("recebeu bblp")
        pkt.show()
        bblp=pkt.getLayer(BBLP)
        networkGraph.UpdateNode(bblp.extract_routes())

def start_router():    
    threading.Thread(target=send_routes, daemon=True).start()
    print(RouterNeighbors)
    for router in RouterNeighbors:
        print(f"Iniciando sniff na interface: {RouterNeighbors[router]}")
        #threading.Thread(target=sniff, kwargs={'prn': receive_routes, 'iface':RouterNeighbors[router]}, daemon=True).start()
        threading.Thread(target=sniff, kwargs={'prn':lambda pkt: pkt.show(), 'store':0}, daemon=True).start()

    print("threads inicializadas")
    while True:
        time.sleep(1)  

def run_router(initialRouterTable):
    for lines in initialRouterTable.routeList:
        RouterNeighbors[lines.nextRouter]=lines.interface
    global networkGraph
    networkGraph = NetworkGraph(initialRouterTable)
    networkGraph.PrintGraph()
    start_router()

if __name__ == "__main__":
    interfaces = get_if_list()
    print("Available interfaces:", interfaces)

    if len(sys.argv) < 1:
        print("ERRO")
        sys.exit(1)

    routerName = sys.argv[1]
    initialRouterTable=RouterTable(routerName)
    for tableLine in globalRouteTable[routerName]:
        initialRouterTable.addRoute(tableLine=tableLine)

    run_router(initialRouterTable=initialRouterTable)
  

