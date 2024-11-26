import heapq
from scapy.all import *
import time
import threading
import subprocess
import ipaddress

NetWork = {'RouterA': '10.1.1.0', 'RouterB': '10.2.2.0', "hostA":'10.1.1.0', "hostB":"10.2.2.0", "RouterC":"10.13.13.0"}  # pode ser setado manualmente é igual para todos os roteadores

Interfaces = {
    ("RouterA", "RouterC"): "r1-eth2", ("RouterC", "RouterA"): "r3-eth1",
    ("RouterB", "RouterC"): "r2-eth2", ("RouterC", "RouterB"): "r3-eth2",
    ("hostA","RouterA"): "h1-eth0", ("RouterA","hostA"): "r1-eth0",
    ("hostB","RouterB"): "h2-eth0", ("RouterB","hostB"): "r2-eth0"
}  # pode ser setado manualmente pois é unica para toda a rede

InterfacesIP = {
    "r1-eth2": "10.12.12.1",
    "r3-eth1": "10.12.12.254",
    "r2-eth2": "10.13.13.1",
    "r3-eth2": "10.13.13.254",
    "h1-eth0": "10.1.1.1",
    "h2-eth0": "10.2.2.1",
    "r1-eth0": "10.1.1.254",
    "r2-eth0": "10.2.2.254"
}


RouterNeighbors = {}  # vizinhos desse roteador e interface entre eles

networkGraph = None


class TableLine:
    def __init__(self, network, interface, nextRouter, weight):
        self.network = network  # rede de destino
        self.interface = interface  # interface que liga com o próximo roteador
        self.nextRouter = nextRouter
        self.weight = weight


globalRouteTable = {
    "RouterA": [TableLine("10.13.13.0", "r1-eth2", "RouterC", 1), TableLine('10.1.1.0', 'r1-eth0', "hostA",1)],
    "RouterB": [TableLine("10.1.1.0", "r2-eth2", "RouterC", 5), TableLine('10.2.2.0', 'r2-eth0', "hostB",5)],
    "RouterC": [TableLine("10.1.1.0", "r3-eth1", "RouterA", 7), TableLine('10.2.2.0', 'r3-eth2', "RouterB",7)]
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
    fields_desc = [
        IPField("destinationNetwork", "0.0.0.0"),  # Agora usa IPField
        StrFixedLenField("nextRouter", "", length=10),
        StrFixedLenField("interface", "", length=10),
        IntField("weight", 0)
    ]

class BBLP(Packet):
    name = "BBLP"
    fields_desc = [
        StrFixedLenField("routerName", "Router", length=10),  # Nome do roteador
        IntField("routeCount", 0),  # Número de rotas
    ]

    def SetRouterName(self, name):
        self.routerName = name

    def add_route(self, destinationNetwork, nextRouter, interface, weight):
        route_entry = BBLP_TABLE_LINE(
            destinationNetwork=destinationNetwork,
            nextRouter=nextRouter,
            interface=interface,
            weight=weight
        )
        self.add_payload(route_entry)
        self.routeCount += 1

    @staticmethod
    def decode_raw_to_routes(raw_data):
        router_table_lines = []
        entry_size = 28  # Tamanho de cada entrada no campo Raw (4 + 10 + 10 + 4)
        
        def clean_field(field):
            """
            Decodifica bytes para string UTF-8, remove null bytes e espaços extras.
            """
            if isinstance(field, bytes):
                return field.decode('utf-8').strip().replace('\x00', '')
            return field.strip().replace('\x00', '')
        
        while len(raw_data) >= entry_size:
            # Extraindo os campos
            destination_network = str(ipaddress.IPv4Address(raw_data[:4]))
            next_router = clean_field(raw_data[4:14])
            interface = clean_field(raw_data[14:24])
            weight = int.from_bytes(raw_data[24:28], byteorder='big')
            
            # Criando uma linha de tabela de roteamento
            router_table_lines.append(
                TableLine(
                    network=destination_network,
                    interface=interface,
                    nextRouter=next_router,
                    weight=weight
                )
            )
            
            # Avançando para a próxima entrada
            raw_data = raw_data[entry_size:]
        
        return router_table_lines

    def extract_routes(self):
        def clean_field(field):
            """
            Decodifica bytes para string UTF-8, remove null bytes e espaços extras.
            """
            if isinstance(field, bytes):
                return field.decode('utf-8').strip().replace('\x00', '')
            return field.strip().replace('\x00', '')

        router_name = clean_field(self.routerName)
        router_table = RouterTable(router_name)
        
        # Processa a primeira linha da tabela, já interpretada corretamente
        payload = self.payload
        while isinstance(payload, BBLP_TABLE_LINE):
            router_table.addRoute(
                TableLine(
                    network=clean_field(payload.destinationNetwork),
                    interface=clean_field(payload.interface),
                    nextRouter=clean_field(payload.nextRouter),
                    weight=payload.weight
                )
            )
            payload = payload.payload  # Move para o próximo item
        
        # Processa as rotas no campo Raw
        if isinstance(payload, Raw):
            raw_routes = BBLP.decode_raw_to_routes(payload.load)
            for route in raw_routes:
                router_table.addRoute(route)
        
        return router_table


BBLP_PROTOCOL_NUMBER=200
bind_layers(IP, BBLP, proto=BBLP_PROTOCOL_NUMBER)
bind_layers(BBLP, BBLP_TABLE_LINE)


def receive_routes(pkt):
    if BBLP in pkt:
        bblp_packet = pkt[BBLP]
        received_router_name = bblp_packet.routerName.decode('utf-8').strip().replace('\x00', '')
        local_router_name = networkGraph.routerName.strip().replace('\x00', '')

        if received_router_name==local_router_name:
            return
        bblp_packet.show()
        routerTable=bblp_packet.extract_routes()
        print("RECEBEU PACOTE DO ROTEADOR" ,routerTable.name)
        for line in routerTable.routeList:
            print(f"Rede de destino: {line.network}")
            print(f"Próximo roteador: {line.nextRouter}")
            print(f"Interface: {line.interface}")
            print(f"Peso: {line.weight}")
            print("-" * 40)
        networkGraph.UpdateNode(routerTable)
        new_table=networkGraph.Dijkstra()
        print("//////////////////////////")
        print(new_table.name)
        for line in new_table.routeList:
            print(line.network, line.nextRouter, line.interface, line.weight)
        print("\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
        
        # Atualiza as rotas no Mininet com base na tabela de rotas atualizada
        for line in networkGraph.graph[networkGraph.routerName]:
            try:
                destination_network = line.network
                next_router = line.nextRouter

                # Determine the correct gateway IP
                interface_pair = (networkGraph.routerName, next_router)
                interface_name = Interfaces.get(interface_pair)

                if not interface_name:
                    print(f"Error: Interface between {networkGraph.routerName} and {next_router} not found.")
                    continue

                gateway_ip = InterfacesIP.get(interface_name)

                if not gateway_ip:
                    print(f"Error: Gateway IP for interface {interface_name} not found in InterfacesIP.")
                    continue

                # Build the command
                cmd = [
                    "ip", "route", "replace",
                    destination_network,
                    "via", gateway_ip,
                    "dev", interface_name
                ]

                # Execute the command
                subprocess.run(cmd, check=True)
                print(f"Route to {destination_network} via {gateway_ip} on {interface_name} updated successfully.")

            except Exception as e:
                print(f"Error updating route for {line.network}: {e}")



def send_routes():
    while True:
        #try:
        # Create the BBLP packet
        print("GRAFO ATUAL")
        print("="*40)
        networkGraph.PrintGraph()
        print("0"*40)
        bblp_pkt = BBLP()
        bblp_pkt.SetRouterName(networkGraph.routerName)
        for line in networkGraph.graph[networkGraph.routerName]:
            bblp_pkt.add_route(
                destinationNetwork=line.network,
                nextRouter=line.nextRouter,
                interface=line.interface,
                weight=line.weight
            )
        # Send the packet to all neighbors
        for router, iface in RouterNeighbors.items():
            print("??????????????????????")
            print((router,networkGraph.routerName), Interfaces[(router,networkGraph.routerName)], InterfacesIP[Interfaces[(router,networkGraph.routerName)]] )
            dst_ip = InterfacesIP[Interfaces[(router,networkGraph.routerName)]]  #interface de destino, exemplo enviar r1->r2  entao interface de destino e a interface que liga r2 a r1
            ip_packet = IP(dst=dst_ip, proto=BBLP_PROTOCOL_NUMBER) / bblp_pkt
            send(ip_packet)
            print(f"Route table sent to {dst_ip} via {iface}")
            print("!!!!!!!!!!!!!!!!!!!!!!!")


        #except Exception as e:
            #print(f"Error in send_routes: {e}")
        time.sleep(5)



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
                    'filter': f"ip"
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
