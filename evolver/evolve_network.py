import netaddr
from evolve_log import *

logger = GetLogger()

class Network(object):

     def __init__(self):
        self.vr = None
        self.ipv4 = None
        self.ipv6 = None

     def AddIpv4(self, addr, offset=0):
        self.ipv4 = netaddr.IPNetwork(addr)
        logger.debug("IP: %s" % self.ipv4.ip)
        if offset:
            #offset <<= (32 - self.ipv4.prefixlen)
            self.ipv4.__iadd__(offset)
            logger.debug("IP: %s, offset: %s" % (self.ipv4.ip, offset))
 
     def AddIpv6(self, addr, offset=0):
        self.ipv6 = netaddr.IPNetwork(addr)
        if offset:
            #offset <<= (128 - self.ipv6.prefixlen)
            self.ipv6.__iadd__(offset)
            logger.debug("IP: %s, offset: %s" % (self.ipv6.ip, offset))

     def Display(self):
        if self.ipv4:
            logger.debug("IPv4 - Network: %s, Broadcast: %s, Size %s, Vr %s" % (
                self.ipv4.network, self.ipv4.broadcast, self.ipv4.size, self.vr))
        if self.ipv6:
            logger.debug("IPv6 - Network: %s, Broadcast: %s, Prefix Length: %s, Vr %s" % (
                self.ipv6.network, self.ipv6.broadcast, self.ipv6.prefixlen, self.vr))


class Connectivity(object):

    def __init__(self):
        self.vlan = None
        self.mtus = [ ]
        self.port_channel = None
        self.networks = [ ]
        net_a = Network()
        net_b = Network()
        self.networks.append(net_a)
        self.networks.append(net_b)

    def AddIpv4Networks(self, nets):
        assert len(nets) == 2
        self.networks[0].AddIpv4(nets[0])
        self.networks[1].AddIpv4(nets[1])

    def AddIpv6Networks(self, nets):
        assert len(nets) == 2
        self.networks[0].AddIpv6(nets[0])
        self.networks[1].AddIpv6(nets[1])

    def AddVrs(self, vrs):
        assert len(vrs) == 2
        self.networks[0].vr = vrs[0]
        self.networks[1].vr = vrs[1]

    def Display(self):
        for n in self.networks:
            n.Display()


class Loopback(object):

    def __init__(self):
        self.vr = None
        self.addr = None


class Route(object):

    def __init__(self, type):
        self.type = type
        self.node = None
        self.network_from = Network()
        self.network_to = Network()
        self.network_via = Network()
 
    def AddRoute(self):
        if self.type == "static":
            net_from = self.network_from
            net_to = self.network_to
            net_via = self.network_via
            self.node.AddRoute(net_from, net_to, net_via)
            self.node.AddRoute(net_from, net_to, net_via, 6)

    def CheckRoute(self):
        if self.node.PingCheck(self.network_from, self.network_to):
            logger.error("Ping check failed")
            assert False
        if self.node.PingCheck(self.network_from, self.network_to, 6):
            logger.error("Ping check failed")
            assert False
