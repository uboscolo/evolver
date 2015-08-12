import xml.etree.ElementTree as ET
from evolve_log import *
from evolve_host import *
from evolve_network import *
from evolve_interfaces import *

logger = GetLogger()

class Parser(object):

    def __init__(self, xml_file):
        self.xml_file = xml_file

    def __AddHosts(self, system, tag):
        assert 'name' in tag.attrib.keys()
        assert 'domain' in tag.attrib.keys()
        assert 'type' in tag.attrib.keys()
        name = tag.attrib['name']
        domain = tag.attrib['domain']
        type = tag.attrib['type']
        if type == "debian":
            new_host = DebianHost(name)
        elif type == "staros":
            new_host = StarOsHost(name)
        elif type == "switch":
            new_host = Switch(name)
        else: 
            logger.error("Unkwnon host type %s" % type)
            assert False
        if 'configure' in tag.attrib.keys() and tag.attrib['configure'] == "yes":
            new_host.verify_only = False
        for next_tag in tag:
            assert next_tag.tag == "make"
            name = next_tag.attrib['name']
            model = next_tag.attrib['model']
            type = next_tag.attrib['type']
            m = Make(name)
            m.model = model
            m.type = type
            new_host.make = m
        new_host.domain = domain
        system.AddEquipment(new_host)

    def __AddLinks(self, system, tag):
        assert 'bandwidth' in tag.attrib.keys()
        bw = tag.attrib['bandwidth']
        nodes = [ ]
        intfs = [ ]
        assert 'node_a' in tag.attrib.keys()
        assert 'node_b' in tag.attrib.keys()
        assert 'interface_a' in tag.attrib.keys()
        assert 'interface_b' in tag.attrib.keys()
        nodes.append(tag.attrib['node_a'])
        intfs.append(tag.attrib['interface_a'])
        nodes.append(tag.attrib['node_b'])
        intfs.append(tag.attrib['interface_b'])
        # create Interface and add to host
        name = "Link %s:%s - %s:%s" % (nodes[0], intfs[0], nodes[1], intfs[1])
        logger.debug("Adding link: %s" % name)
        new_link = Link(name)
        system.AddLink(new_link)
        for index in range(0,2):
            node = system.equipment_by_name[nodes[index]]
            new_link.nodes.append(node)
            node.AddInterface(intfs[index], bw)
            intf = node.interfaces_by_name[intfs[index]] 
            new_link.interfaces.append(intf)
        for next_tag in tag:
            assert next_tag.tag == "connectivity"
            assert 'vlan' in next_tag.attrib.keys()
            c = Connectivity()
            c.vlan = next_tag.attrib['vlan']
            mtu_a = None
            mtu_b = None
            if 'mtu_a' in next_tag.attrib.keys():
                mtu_a = next_tag.attrib['mtu_a']
            if 'mtu_b' in next_tag.attrib.keys():
                mtu_b = next_tag.attrib['mtu_b']
            c.mtus.append(mtu_a)
            c.mtus.append(mtu_b)
            if 'port_channel' in next_tag.attrib.keys():
                c.port_channel = next_tag.attrib['port_channel']
            for sub_tag in next_tag:
                assert sub_tag.tag == "network"
                if 'ipv4_a' in sub_tag.attrib.keys():
                    assert 'ipv4_b' in sub_tag.attrib.keys()
                    nets = [ ]
                    nets.append(sub_tag.attrib['ipv4_a'])
                    nets.append(sub_tag.attrib['ipv4_b'])
                    c.AddIpv4Networks(nets)
                if 'ipv6_a' in sub_tag.attrib.keys():
                    assert 'ipv6_b' in sub_tag.attrib.keys()
                    nets = [ ]
                    nets.append(sub_tag.attrib['ipv6_a'])
                    nets.append(sub_tag.attrib['ipv6_b'])
                    c.AddIpv6Networks(nets)
                assert 'vr_a' in sub_tag.attrib.keys()
                assert 'vr_b' in sub_tag.attrib.keys()
                vrs = [ ]
                vrs.append(sub_tag.attrib['vr_a'])
                vrs.append(sub_tag.attrib['vr_b'])
                c.AddVrs(vrs)
            new_link.AddConnectivity(c)

    def __AddRoutes(self, system, tag):
        assert 'type' in tag.attrib.keys()
        assert 'node_from' in tag.attrib.keys()
        assert 'node_to' in tag.attrib.keys()
        type = tag.attrib['type']
        node_f = tag.attrib['node_from'] 
        node_t = tag.attrib['node_to'] 
        node_obj_f = system.equipment_by_name[node_f]
        node_obj_t = system.equipment_by_name[node_t]
        num_routes = 1
        if 'num' in tag.attrib.keys():
            num_routes = int(tag.attrib['num'])
        for r in range(num_routes):
            new_route = Route(type)
            new_route.node = node_obj_f
            system.AddRoute(new_route)
            if type == "static":
                assert 'node_via' in tag.attrib.keys()
                node_v = tag.attrib['node_via'] 
            for next_tag in tag:
                assert next_tag.tag == "network"
                assert 'vr_from' in next_tag.attrib.keys()
                assert 'vr_to' in next_tag.attrib.keys()
                vr_f = next_tag.attrib['vr_from']
                vr_t = next_tag.attrib['vr_to']
                num_loop = 1
                if 'num_from' in next_tag.attrib.keys():
                    num_loop = int(next_tag.attrib['num_from'])
                new_route.network_from.vr = vr_f
                new_route.network_to.vr = vr_t
                if type == "static":
                    assert 'vr_via' in next_tag.attrib.keys()
                    new_route.network_via.vr = next_tag.attrib['vr_via']
                if 'v4_addr_from' in next_tag.attrib.keys():
                    assert 'v4_addr_to' in next_tag.attrib.keys()
                    addr_f = next_tag.attrib['v4_addr_from'] 
                    addr_t = next_tag.attrib['v4_addr_to'] 
                    node_obj_f.AddLoopback(addr_f, vr_f, num_loop)
                    node_obj_t.AddLoopback(addr_t, vr_t)
                    new_route.network_from.AddIpv4(addr_f)
                    new_route.network_to.AddIpv4(addr_t, r)
                    if type == "static":
                        assert 'v4_addr_via' in next_tag.attrib.keys()
                        addr_v = next_tag.attrib['v4_addr_via'] 
                        new_route.network_via.AddIpv4(addr_v)
                elif 'v6_addr_from' in next_tag.attrib.keys():
                    assert 'v6_addr_to' in next_tag.attrib.keys()
                    addr_f = next_tag.attrib['v6_addr_from'] 
                    addr_t = next_tag.attrib['v6_addr_to'] 
                    node_obj_f.AddLoopback(addr_f, vr_f, num_loop)
                    node_obj_t.AddLoopback(addr_t, vr_t)
                    new_route.network_from.AddIpv6(addr_f)
                    new_route.network_to.AddIpv6(addr_t, r)
                    if type == "static":
                        assert 'v6_addr_via' in next_tag.attrib.keys()
                        addr_v = next_tag.attrib['v6_addr_via'] 
                        new_route.network_via.AddIpv6(addr_v)
            new_route.AddRoute()

    def ParseXml(self):
        tree = ET.parse(self.xml_file)
        root_tag = tree.getroot()
        assert root_tag.tag == "system"

        assert 'name' in root_tag.attrib.keys()
        name = root_tag.attrib['name']
        sys = System(name)
        for next_tag in root_tag:
            if next_tag.tag == "device":
                self.__AddHosts(sys, next_tag)
            elif next_tag.tag == "link":
                self.__AddLinks(sys, next_tag)
            elif next_tag.tag == "route":
                self.__AddRoutes(sys, next_tag)
            else: 
                logger.error("Unkwnon tag %s" % next_tag.tag)
                assert False
        return sys


class System(object):

    def __init__(self, name):
        self.name = name
        self.equipment = [ ]
        self.equipment_by_name = { }
        self.links = [ ]
        self.routes = [ ]
   
    def AddEquipment(self, host):
        self.equipment.append(host)
        self.equipment_by_name[host.name] = host
        host.Connect()

    def AddLink(self, link):
        self.links.append(link)

    def AddRoute(self, route):
        self.routes.append(route)

    def Destroy():
        pass

    def Display(self): 
        for e in self.equipment:
            logger.debug("Host %s" % e.name)
        for l in self.links:
            l.Display()

    def CheckConnectivity(self): 
        for l in self.links:
            logger.debug("Link name %s" % l.name)
            l.CheckConnectivity()

    def CheckRouting(self): 
        for r in self.routes:
            r.CheckRoute()


class Link(object):

    def __init__(self, name):
        self.name = name
        self.bandwidth = None
        self.nodes = [ ]
        self.interfaces = [ ]
        self.connections = [ ]

    def AddConnectivity(self, conn):
        logger.debug("Adding connectivity vlan %s" % conn.vlan)
        self.connections.append(conn)
        for i in range(0, 2):
            node = self.nodes[i]
            intf = self.interfaces[i]
            net = conn.networks[i]
            mtu = conn.mtus[i]
            intf.AddLink(node, conn, net, mtu)
            intf.AddConnectivity(node, conn, net)

    def CheckConnectivity(self):
        node = self.nodes[0]
        for c in self.connections:
            local_net = c.networks[0]  
            remote_net = c.networks[1]  
            if node.PingCheck(local_net, remote_net):
                logger.error("Ping check failed")
                assert False
            if node.PingCheck(local_net, remote_net, 6):
                logger.error("Ping check failed")
                assert False
 
    def Display(self):
        logger.debug("Link %s" % self.name)
        for n in self.nodes:
            logger.debug("Node %s" % n.name)
        for n in self.interfaces:
            logger.debug("Interfaces %s" % n.name)
        for c in self.connections:
            c.Display()
