from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from Router import Router

class AdvancedTopo(Topo):
    def build(self, **_opts):
        # Criando roteadores
        r1 = self.addHost('r1', ip="1.1.1.0")
        r2 = self.addHost('r2', ip="2.2.2.0")

        # Criando hosts
        h1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')
        h2 = self.addHost('h2', ip='10.2.2.1/24', defaultRoute='via 10.2.2.254')

        # Links
        self.addLink(r1, r2, intfName1='r1-eth1', params1={'ip': '10.11.11.1/24'},
                     intfName2='r2-eth1', params2={'ip': '10.11.11.2/24'})
        self.addLink(h1, r1, intfName1='h1-eth0', params1={'ip': '10.1.1.1/24'},
                     intfName2='r1-eth0', params2={'ip': '10.1.1.254/24'})
        self.addLink(h2, r2, intfName1='h2-eth0', params1={'ip': '10.2.2.1/24'},
                     intfName2='r2-eth0', params2={'ip': '10.2.2.254/24'})

# Função para obter as informações da rede dos roteadores
def get_network_info(router):
    network_info = {}
    for intf in router.intfList():
        ip = intf.IP()
        peer_ip = router.connectionsTo(intf)[0][1].IP() if router.connectionsTo(intf) else None
        network_info[intf.name] = {
            'network': ip,
            'interface': intf.name,
            'destination': peer_ip  # Endereço IP do roteador oposto
        }
    return network_info

# Função principal do Mininet
def run():
    net = Mininet(topo=AdvancedTopo(), controller=None)
    net.start()

    # Inicializa cada roteador com informações da topologia
    r1 = net.get('r1')
    r2 = net.get('r2')

    # Obter informações de rede de cada roteador
    r1_network_info = get_network_info(r1)
    r2_network_info = get_network_info(r2)

    # Ativar encaminhamento IP nos roteadores
    for router in [r1, r2]:
        router.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Inicializar objetos Router com os vizinhos (r2 é vizinho de r1 e vice-versa)
    router1 = Router(node=r1, network_info=r1_network_info)
    router2 = Router(node=r2, network_info=r2_network_info)

    # Iniciar os roteadores
    router1.start()
    router2.start()

    # CLI do Mininet
    CLI(net)
    print("Fim da execução.")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
