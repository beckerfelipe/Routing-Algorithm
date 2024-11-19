from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from scapy.all import *

from Router import IP, BBLP, BBLP_PROTOCOL_NUMBER, BBLP_TABLE_LINE

class AdvancedTopo(Topo):
    "dois roteadores com dois hosts"

    def build(self, **_opts):
        # Criando roteadores
        r1 = self.addHost('r1', ip=None)  # Roteador 1
        r2 = self.addHost('r2', ip=None)  # Roteador 2

        # Criando hosts
        h1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')  # Host 1
        h2 = self.addHost('h2', ip='10.2.2.1/24', defaultRoute='via 10.2.2.254')  # Host 2

        # Adicionando links entre roteadores e hosts
        self.addLink(r1, r2, intfName1='r1-eth1', params1={'ip': '10.11.11.1/24'},
                     intfName2='r2-eth1', params2={'ip': '10.11.11.2/24'})  # Link entre r1 e r2

        # Link entre r1 e h1
        self.addLink(h1, r1, intfName1='h1-eth0', params1={'ip': '10.1.1.1/24'},
                     intfName2='r1-eth0', params2={'ip': '10.1.1.254/24'})

        # Link entre r2 e h2
        self.addLink(h2, r2, intfName1='h2-eth0', params1={'ip': '10.2.2.1/24'},
                     intfName2='r2-eth0', params2={'ip': '10.2.2.254/24'})


# Função principal do Mininet
def run():
    "Topologia avançada com dois roteadores e dois hosts"
    net = Mininet(topo=AdvancedTopo(), controller=None)
    
    # Desabilitar recursos de offload para o correto manuseio de pacotes
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K ' + itf.name + ' tx off rx off')
    
    net.start()
    
    # Adicionar rotas estáticas nos roteadores
    info("Adicionando rota estática em r1 para a rede de h2...\n")
    r1 = net.get('r1')
    r1.cmd('ip route add 10.2.2.0/24 via 10.11.11.2')
    
    info("Adicionando rota estática em r2 para a rede de h1...\n")
    r2 = net.get('r2')
    r2.cmd('ip route add 10.1.1.0/24 via 10.11.11.1')

    for router in ['r1', 'r2']:
        net[router].cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Iniciar CLI para interação com a rede
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')


    bind_layers(IP, BBLP, proto=BBLP_PROTOCOL_NUMBER)
    bind_layers(BBLP, BBLP_TABLE_LINE)
    run()

