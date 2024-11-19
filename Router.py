import heapq
from scapy.all import *
import time
import threading
import subprocess
import ipaddress

NetWork = {'RouterA': '10.1.1.0', 'RouterB': '10.2.2.0', "hostA":'10.1.1.0', "hostB":"10.2.2.0"}  # pode ser setado manualmente é igual para todos os roteadores

Interfaces = {
    ("RouterA", "RouterB"): "r1-eth1", ("RouterB", "RouterA"): "r2-eth1",
    ("hostA-RouterA"): "h1-eth0", ("RouterA-hostA"): "r1-eth0",
    ("hostB-RouterB"): "h2-eth0", ("RouterB-hostB"): "r2-eth0"
}  # pode ser setado manualmente pois é unica para toda a rede

RouterNeighbors = {}  # vizinhos desse roteador e interface entre eles

networkGraph = None


class TableLine:
    def __init__(self, network, interface, nextRouter, weight):
        self.network = network  # rede de destino
        self.interface = interface  # interface que liga com o próximo roteador
        self.nextRouter = nextRouter
        self.weight = weight


globalRouteTable = {
    "RouterA": [TableLine("10.2.2.0", "r1-eth1", "RouterB", 2), TableLine('10.1.1.0', 'r1-eth0', "hostA",3)],
    "RouterB": [TableLine("10.1.1.0", "r2-eth1", "RouterA", 5), TableLine('10.2.2.0', 'r2-eth0', "hostB",3)]
}  # para cada roteador seus vizinhos

class RouterTable:
    def __init__(self, name):
        self.name = name  # nome do host/roteador atual
        self.routeList = []

    def addRoute(self, tableLine):
        self.routeList.append(tableLine)

    def changeLine(self, old, new):
        index = self.routeList.index(old)
        self.routeList[index] = new


class NetworkGraph:
    def __init__(self, routerTable):
        self.graph = {}
        self.routerName = routerTable.name
        self.graph[self.routerName] = []
        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(
                tableLine.network, tableLine.interface, tableLine.nextRouter, tableLine.weight))

    def PrintGraph(self):
        for node in self.graph:
            print(node)
            for line in self.graph[node]:
                print(line.network, line.nextRouter, tableLine.interface, line.weight)

    def UpdateNode(self, routerTable):
        if routerTable.name not in self.graph:
            self.graph[routerTable.name] = []

        self.graph[routerTable.name].clear()

        for tableLine in routerTable.routeList:
            self.graph[routerTable.name].append(TableLine(
                tableLine.network, tableLine.nextRouter, tableLine.interface, tableLine.weight))

    def Dijkstra(self):  # retorna a tabela de rotas desse roteador baseado no grafo da rede
        start_router = self.routerName
        distances = {start_router: 0}
        previous_nodes = {start_router: None}
        priority_queue = [(0, start_router)]

        while priority_queue:
            current_distance, current_router = heapq.heappop(priority_queue)

            if current_distance > distances.get(current_router, float('inf')):
                continue

            for line in self.graph.get(current_router, []):
                weight = line.weight
                nextHop = line.nextRouter
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
                print(start_router, next_hop)
                new_router_table.addRoute(TableLine(
                    NetWork.get(router), Interfaces.get((start_router, next_hop)), next_hop, distance))
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
        if networkGraph is not None:
            self.routerName = networkGraph.routerName
            self.routeCount = 0

    def add_route(self, destinationNetwork, nextRouter, interface, weight):
        route_entry = BBLP_TABLE_LINE(
            destinationNetwork=destinationNetwork,
            nextRouter=nextRouter,
            interface=interface,
            weight=weight
        )
        self.add_payload(route_entry)
        self.routeCount += 1

    def extract_routes(self):  # retorna RouterTable
        routerTable = RouterTable(self.routerName.decode('utf-8').strip())
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
    
BBLP_PROTOCOL_NUMBER = 200


bind_layers(IP, BBLP, proto=BBLP_PROTOCOL_NUMBER)
bind_layers(BBLP, BBLP_TABLE_LINE)

# TODO: quando a topologia estiver correta, criar para cada roteador o networkGraph e corrigir esses métodos de enviar e receber rotas
# com isso pronto, deve ser possível cada roteador ficar enviando a sua tabela de rotas e receber a dos outros
# para cada tabela recebida, atualizar o nó do roteador e calcular Dijkstra novamente


def parse_raw_to_bblp(raw_packet):
    """
    Parse a Raw packet payload into a BBLP packet, including its routing table lines.
    """
    try:
        # Verifique se o pacote tem a camada Raw
        if not raw_packet.haslayer(Raw):
            print("Erro: Pacote não contém camada Raw.")
            return None

        raw_payload = raw_packet[Raw].load  # Pegue os bytes da carga útil
        print(f"Raw payload: {raw_payload}")

        # Parse o cabeçalho BBLP
        router_name = raw_payload[:10].decode('utf-8').strip('\x00')
        route_count = int.from_bytes(raw_payload[10:14], byteorder='big')
        print(f"Router Name: {router_name}, Route Count: {route_count}")

        # Crie um objeto BBLP
        bblp_packet = BBLP()

        # Parse cada entrada da tabela de roteamento
        offset = 14
        for _ in range(route_count):
            dest_network = raw_payload[offset:offset+15].decode('utf-8').strip('\x00')
            next_router = raw_payload[offset+15:offset+25].decode('utf-8').strip('\x00')
            iface = raw_payload[offset+25:offset+35].decode('utf-8').strip('\x00')
            weight = int.from_bytes(raw_payload[offset+35:offset+39], byteorder='big')

            # Adicione a entrada à tabela de rotas no pacote BBLP
            bblp_packet.add_route(dest_network, next_router, iface, weight)
            offset += 39
        print("Pacote BBLP reconstruído:")
        bblp_packet.show()  # Exibe o pacote para debug
        print("")
        print("")
        return bblp_packet

    except Exception as e:
        print(f"Erro ao processar pacote Raw para BBLP: {e}")
        return None
    



def receive_routes(pkt):
    if pkt.haslayer(Raw):
        print("Raw packet received. Attempting to parse into BBLP...")
        bblp_packet = parse_raw_to_bblp(pkt)
        if bblp_packet:
            if bblp_packet.routerName.decode('utf-8').strip()== networkGraph.routerName:
                print(f"Ignorando pacote enviado pelo próprio roteador: {bblp_packet.routerName.decode('utf-8').strip()}")
                return

            networkGraph.UpdateNode(bblp_packet.extract_routes())
            networkGraph.Dijkstra()
		
            # AQUI O SEXO DEFINE SE VOU PULAR A PRIMEIRA LINHA
            # DO GRAFO OU NAO, A PRIMEIRA APARENTEMENTE SEMPRE DA INVALID GATEWAY
            # A SEGUNDA NAO, MAS NAO ENTENDO TAMBEM, TA ERRADO O JEITO
            # Q TA SENDO ESCRITO
            # SE SEXO FOR MAIOR Q 1 ELE IGNORA A PRIMEIRA

            sexo = 0
            # Atualiza as rotas no Mininet com base na tabela de rotas atualizada
            for line in networkGraph.graph[networkGraph.routerName]:
                sexo += 1
                if(sexo>1):
                        
                    try:
                        destination_network = line.network
                        gateway_ip = NetWork.get(line.nextRouter)  # Gateway é o próximo roteador
                        interface = line.interface
                        if not gateway_ip:
                            print(f"Error: Gateway IP {gateway_ip} for {line.interface} not found in NetWork.")
                            continue

                        # Build the command
                        cmd = [
                            "ip", "route", "replace",
                            destination_network,
                            "via", gateway_ip,
                            "dev", interface
                        ]

                        # Execute the command
                        subprocess.run(cmd, check=True)
                        print(f"Route to {destination_network} via {gateway_ip} on {interface} updated successfully.")

                    except Exception as e:
                        print(f"Error updating route for {line.network}: {e}")  
        else:
            print("Failed to parse Raw packet into BBLP.")
    else:
        print("Received an unrelated packet.")



def send_routes():
    while True:
        try:
            if not networkGraph.routerName:
                raise ValueError("Router name (routerName) is not defined.")

            # Create the BBLP packet
            bblp_pkt = BBLP()
            for line in networkGraph.graph[networkGraph.routerName]:
                bblp_pkt.add_route(
                    destinationNetwork=line.network,
                    nextRouter=line.nextRouter,
                    interface=line.interface,
                    weight=line.weight
                )
	        
            print("ENVIOU PACOTE BBLP")
            bblp_pkt.show()
            print("")
            print("")
            # Send the packet to all neighbors
            for router, iface in RouterNeighbors.items():
                dst_ip = NetWork[router]  # Use correct destination IP
                ip_packet = IP(dst=dst_ip, proto=BBLP_PROTOCOL_NUMBER) / bblp_pkt
                send(ip_packet, iface=iface)
                print(f"Route table sent to {dst_ip} via {iface}")

        except Exception as e:
            print(f"Error in send_routes: {e}")
        time.sleep(15)



def start_router():
    try:
        threading.Thread(target=send_routes, daemon=True).start()
        print("Available interfaces:", get_if_list())
        print("Router neighbors:", RouterNeighbors)

        # Start sniffing threads for each neighbor
        for neighbor, iface in RouterNeighbors.items():
            if iface not in get_if_list():
                print(f"Error: Interface {iface} not found!")
                continue
            print(f"Starting sniff on interface: {iface} for neighbor {neighbor}")
            threading.Thread(
                target=sniff,
                kwargs={
                    'prn': receive_routes,
                    'iface': iface,
                    'store': 0,
                    'filter': f"ip proto {BBLP_PROTOCOL_NUMBER}"
                },
                daemon=True
            ).start()

        print("Sniffing threads initialized.")
    except Exception as e:
        print(f"Error in start_router: {e}")
    while True:
        time.sleep(1)



def run_router(initialRouterTable):
    for lines in initialRouterTable.routeList:
        RouterNeighbors[lines.nextRouter] = lines.interface
    global networkGraph
    networkGraph = NetworkGraph(initialRouterTable)
    start_router()


if __name__ == "__main__":
    interfaces = get_if_list()
    print("Available interfaces:", interfaces)

    if len(sys.argv) < 1:
        print("ERRO")
        sys.exit(1)

    routerName = sys.argv[1]
    initialRouterTable = RouterTable(routerName)
    for tableLine in globalRouteTable[routerName]:
        initialRouterTable.addRoute(tableLine=tableLine)

    run_router(initialRouterTable=initialRouterTable)
