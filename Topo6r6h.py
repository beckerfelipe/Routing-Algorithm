#!/usr/bin/env python

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNetwork():

    net = Mininet(topo=None, build=False, controller=None)

    info('*** Add routers\n')
    r1 = net.addHost('r1', ip='10.10.1.0/24')
    r2 = net.addHost('r2', ip='10.10.2.0/24')
    r3 = net.addHost('r3', ip='10.10.3.0/24')
    r4 = net.addHost('r4', ip='10.10.4.0/24')
    r5 = net.addHost('r5', ip='10.10.5.0/24')
    r6 = net.addHost('r6', ip='10.10.6.0/24')

    for router in [r1, r2, r3, r4, r5, r6]:
        router.cmd('sysctl -w net.ipv4.ip_forward=1')

    info( '*** Add hosts\n')

    h1 = net.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.10.1.1')
    h2 = net.addHost('h2', ip='10.2.2.1/24', defaultRoute='via 10.10.2.1')
    h3 = net.addHost('h3', ip='10.3.3.1/24', defaultRoute='via 10.10.3.1')
    h4 = net.addHost('h4', ip='10.4.4.1/24', defaultRoute='via 10.10.4.1')
    h5 = net.addHost('h5', ip='10.5.5.1/24', defaultRoute='via 10.10.5.1')
    h6 = net.addHost('h6', ip='10.6.6.1/24', defaultRoute='via 10.10.6.1')

    info('*** Add links\n')

    net.addLink(r1, r5, intfName1='r1-r5', params1={'ip': '10.7.7.1/24'}, intfName2='r5-r1', params2={'ip': '10.7.7.2/24'})
    net.addLink(r1, r6, intfName1='r1-r6', params1={'ip': '10.8.8.1/24'}, intfName2='r6-r1', params2={'ip': '10.8.8.2/24'})
    net.addLink(r2, r3, intfName1='r2-r3', params1={'ip': '10.9.9.1/24'}, intfName2='r3-r2', params2={'ip': '10.9.9.2/24'})
    net.addLink(r2, r4, intfName1='r2-r4', params1={'ip': '10.10.10.1/24'}, intfName2='r4-r2', params2={'ip': '10.10.10.2/24'})
    net.addLink(r2, r5, intfName1='r2-r5', params1={'ip': '10.11.11.1/24'}, intfName2='r5-r2', params2={'ip': '10.11.11.2/24'})
    net.addLink(r3, r5, intfName1='r3-r5', params1={'ip': '10.12.12.1/24'}, intfName2='r5-r3', params2={'ip': '10.12.12.2/24'})
    net.addLink(r3, r6, intfName1='r3-r6', params1={'ip': '10.13.13.1/24'}, intfName2='r6-r3', params2={'ip': '10.13.13.2/24'})
    net.addLink(r4, r6, intfName1='r4-r6', params1={'ip': '10.14.14.1/24'}, intfName2='r6-r4', params2={'ip': '10.14.14.2/24'})

    net.addLink(h1, r1, intfName1='h1-eth0', params1={'ip': '10.10.1.1/24'}, intfName2='r1-h1', params2={'ip': '10.10.1.2/24'})
    net.addLink(h2, r2, intfName1='h2-eth0', params1={'ip': '10.10.2.1/24'}, intfName2='r2-h2', params2={'ip': '10.10.2.2/24'})
    net.addLink(h3, r3, intfName1='h3-eth0', params1={'ip': '10.10.3.1/24'}, intfName2='r3-h3', params2={'ip': '10.10.3.2/24'})
    net.addLink(h4, r4, intfName1='h4-eth0', params1={'ip': '10.10.4.1/24'}, intfName2='r4-h4', params2={'ip': '10.10.4.2/24'})
    net.addLink(h5, r5, intfName1='h5-eth0', params1={'ip': '10.10.5.1/24'}, intfName2='r5-h5', params2={'ip': '10.10.5.2/24'})
    net.addLink(h6, r6, intfName1='h6-eth0', params1={'ip': '10.10.6.1/24'}, intfName2='r6-h6', params2={'ip': '10.10.6.2/24'})

    net.build()

    info('*** Configurando rotas estáticas\n')

    r1.cmd('ip route add 10.1.1.0/24 via 10.10.1.2') # r1 para h1 (direto)
    r1.cmd('ip route add 10.2.2.0/24 via 10.7.7.1')  # r1 para h2 (via r5)
    r1.cmd('ip route add 10.4.4.0/24 via 10.8.8.1')  # r1 para h3 (via r6)
    r1.cmd('ip route add 10.6.6.0/24 via 10.8.8.1')  # r1 para h4 (via r6)
    r1.cmd('ip route add 10.7.7.0/24 via 10.7.7.1')  # r1 para h5 (via r5)
    r1.cmd('ip route add 10.9.9.0/24 via 10.8.8.2')  # r1 para h6 (via r6)

    r2.cmd('ip route add 10.1.1.0/24 via 10.11.11.1') # r2 para h1 (via r5)
    r2.cmd('ip route add 10.2.2.0/24 via 10.10.2.2')  # r2 para h2 (direto)
    r2.cmd('ip route add 10.3.3.0/24 via 10.9.9.1')   # r2 para h3 (via r3)
    r2.cmd('ip route add 10.4.4.0/24 via 10.10.10.1') # r2 para h4 (via r4)
    r2.cmd('ip route add 10.5.5.0/24 via 10.11.11.1') # r2 para h5 (via r5)
    r2.cmd('ip route add 10.6.6.0/24 via 10.10.10.1') # r2 para h6 (via r4)

    r3.cmd('ip route add 10.1.1.0/24 via 10.12.12.1') # r3 para h1 (via r5)
    r3.cmd('ip route add 10.2.2.0/24 via 10.9.9.2')   # r3 para h2 (via r2)
    r3.cmd('ip route add 10.3.3.0/24 via 10.10.3.2')  # r3 para h3 (direto)
    r3.cmd('ip route add 10.4.4.0/24 via 10.13.13.1') # r3 para h4 (via r6)
    r3.cmd('ip route add 10.5.5.0/24 via 10.12.12.2') # r3 para h5 (via r5)
    r3.cmd('ip route add 10.6.6.0/24 via 10.13.13.1') # r3 para h6 (via r6)

    r4.cmd('ip route add 10.1.1.0/24 via 10.14.14.1') # r4 para h1 (via r6)
    r4.cmd('ip route add 10.2.2.0/24 via 10.10.10.2') # r4 para h2 (via r2)
    r4.cmd('ip route add 10.3.3.0/24 via 10.14.14.1') # r4 para h3 (via r6)
    r4.cmd('ip route add 10.4.4.0/24 via 10.10.4.2')  # r4 para h4 (direto)
    r4.cmd('ip route add 10.5.5.0/24 via 10.10.10.2') # r4 para h5 (via r2)
    r4.cmd('ip route add 10.6.6.0/24 via 10.14.14.1') # r4 para h6 (via r6)

    r5.cmd('ip route add 10.1.1.0/24 via 10.7.7.2')   # r5 para h1 (via r1)
    r5.cmd('ip route add 10.2.2.0/24 via 10.11.11.2') # r5 para h2 (via r2)
    r5.cmd('ip route add 10.3.3.0/24 via 10.12.12.2') # r5 para h3 (via r3)
    r5.cmd('ip route add 10.4.4.0/24 via 10.11.11.2') # r5 para h4 (via r2)
    r5.cmd('ip route add 10.5.5.0/24 via 10.10.5.2')  # r5 para h5 (direto)
    r5.cmd('ip route add 10.6.6.0/24 via 10.7.7.2')   # r5 para h6 (via r1)

    r6.cmd('ip route add 10.1.1.0/24 via 10.8.8.2')   # r6 para h1 (via r1)
    r6.cmd('ip route add 10.2.2.0/24 via 10.14.14.2') # r6 para h2 (via r4)
    r6.cmd('ip route add 10.3.3.0/24 via 10.13.13.2') # r6 para h3 (via r3)
    r6.cmd('ip route add 10.4.4.0/24 via 10.14.14.2') # r6 para h4 (via r4)
    r6.cmd('ip route add 10.5.5.0/24 via 10.8.8.2')   # r6 para h5 (via r1)
    r6.cmd('ip route add 10.6.6.0/24 via 10.10.6.2')  # r6 para h6 (direto)

    info('*** Post configure switches and hosts\n')
    CLI(net)

    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
