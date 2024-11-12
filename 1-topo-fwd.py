from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class AdvancedTopo(Topo):
    def build(self, **_opts):
        # Criando roteadores
        r1 = self.addHost('r1', ip="10.1.1.254")
        r2 = self.addHost('r2', ip="10.2.2.254")

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

# Função principal do Mininet
def run():
    # Criar e iniciar a rede Mininet
    net = Mininet(topo=AdvancedTopo(), controller=None)
    net.start()

    # Obter roteadores da rede
    r1 = net.get('r1')
    r2 = net.get('r2')
    
    for router in [r1, r2]:
        router.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    for router in [r1,r2]:
        router.cmd("xterm -hold -e 'python3 Router.py' &")


    # CLI do Mininet
    CLI(net)
    print("Fim da execução.")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

