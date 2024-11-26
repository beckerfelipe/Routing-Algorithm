from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from scapy.all import *

from Router import IP, BBLP, BBLP_PROTOCOL_NUMBER, BBLP_TABLE_LINE

class AdvancedTopo(Topo):
    "Dois roteadores existentes com um novo roteador intermediário"

    def build(self, **_opts):
        # Criando roteadores
        r1 = self.addHost('r1', ip=None)  # Roteador 1
        r2 = self.addHost('r2', ip=None)  # Roteador 2
        r3 = self.addHost('r3', ip=None)  # Novo roteador intermediário

        # Criando hosts
        h1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')  # Host 1
        h2 = self.addHost('h2', ip='10.2.2.1/24', defaultRoute='via 10.2.2.254')  # Host 2

        # Adicionando links entre roteadores
        self.addLink(r1, r3, intfName1='r1-eth2', params1={'ip': '10.12.12.1/24'},
                     intfName2='r3-eth1', params2={'ip': '10.12.12.254/24'})  # Link entre r1 e r3
        self.addLink(r2, r3, intfName1='r2-eth2', params1={'ip': '10.13.13.1/24'},
                     intfName2='r3-eth2', params2={'ip': '10.13.13.254/24'})  # Link entre r2 e r3

        # Links entre roteadores e hosts
        self.addLink(h1, r1, intfName1='h1-eth0', params1={'ip': '10.1.1.1/24'},
                     intfName2='r1-eth0', params2={'ip': '10.1.1.254/24'})  # Link entre r1 e h1
        self.addLink(h2, r2, intfName1='h2-eth0', params1={'ip': '10.2.2.1/24'},
                     intfName2='r2-eth0', params2={'ip': '10.2.2.254/24'})  # Link entre r2 e h2


# Função principal do Mininet
def run():
    "Topologia avançada com três roteadores e dois hosts"
    net = Mininet(topo=AdvancedTopo(), controller=None)
    
    # Desabilitar recursos de offload para o correto manuseio de pacotes
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K ' + itf.name + ' tx off rx off')
    
    net.start()
    
    # Ativar o encaminhamento de pacotes nos roteadores
    for router in ['r1', 'r2', 'r3']:
        net[router].cmd('sysctl -w net.ipv4.ip_forward=1')

    # Configurar rotas estáticas nos roteadores
    info("Adicionando rotas estáticas nos roteadores...\n")

    r1 = net.get('r1')
    '''r1.cmd('ip route add 10.2.2.0/24 via 10.12.12.2')  # r1 para h2 via r3
    r1.cmd('ip route add 10.13.13.0/24 via 10.12.12.2')  # r1 para r2 via r3

    r2 = net.get('r2')
    r2.cmd('ip route add 10.1.1.0/24 via 10.13.13.2')  # r2 para h1 via r3
    r2.cmd('ip route add 10.12.12.0/24 via 10.13.13.2')  # r2 para r1 via r3

    r3 = net.get('r3')
    r3.cmd('ip route add 10.1.1.0/24 via 10.12.12.1')  # r3 para r1
    r3.cmd('ip route add 10.2.2.0/24 via 10.13.13.1')  # r3 para r2 via r2'''

    # Iniciar CLI para interação com a rede
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')

    bind_layers(IP, BBLP, proto=BBLP_PROTOCOL_NUMBER)
    bind_layers(BBLP, BBLP_TABLE_LINE)
    run()
