import argparse

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.node import RemoteController
from mininet.topo import Topo
from p4_mininet import P4Host,P4Switch
from p4runtime_switch import P4RuntimeSwitch
from mininet.link import Link,TCLink

CPU_PORT = 255


class IPv6Host(Host):
    """Host that can be configured with an IPv6 gateway (default route).
    """

    def config(self, ipv6, ipv6_gw=None, **params):
        super(IPv6Host, self).config(**params)
        self.cmd('ip -4 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr flush dev %s' % self.defaultIntf())
        self.cmd('ip -6 addr add %s dev %s' % (ipv6, self.defaultIntf()))
        if ipv6_gw:
            self.cmd('ip -6 route add default via %s' % ipv6_gw)
        # Disable offload
        for attr in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" % (self.defaultIntf(), attr)
            self.cmd(cmd)

        def updateIP():
            return ipv6.split('/')[0]

        self.defaultIntf().updateIP = updateIP

    def terminate(self):
        super(IPv6Host, self).terminate() 
        

#
def main():
   # controller = RemoteController('c0', ip="127.0.0.1",port=6653)
    net = Mininet(link=TCLink)
    #net.addController(controller)
    # Leaves
        # gRPC port 50051
    sw1 = net.addSwitch('sw1', cls=P4RuntimeSwitch)
        

        # IPv6 hosts attached to leaf 1
    h1a = net.addHost('h1a',cls=P4Host,mac="00:00:00:00:00:1A")
    h1b = net.addHost('h1b',cls=P4Host,mac="00:00:00:00:00:1B")
    
    net.addLink(h1a, sw1)  # port 3
    net.addLink(h1b, sw1)  # port 4
    h1a.cmd("ifconfig h1a-eth0 11.0.2.2 netmask 255.255.255.0 broadcast 11.0.2.255")
    h1b.cmd("ifconfig h1b-eth0 10.0.2.2 netmask 255.255.255.0 broadcast 10.0.2.255")
    h1a.cmd("ip -4 route add default via 11.0.2.1",
        	"arp -i eth0 -s 11.0.2.1 72:79:26:f0:2a:84"
            'ip -6 addr add f1::3 dev eth0')
    h1b.cmd("ip -4 route add default via 10.0.2.1",
        	"arp -i eth0 -s 10.0.2.1 f6:45:e5:8f:aa:96"
            'ip -6 addr add f2::4 dev eth0')
    
        # IPv6 hosts attached to leaf 2
    net.start()
    CLI(net)
    net.stop()
    


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()
