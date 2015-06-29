import xml.etree.ElementTree as ET
import netaddr
import re
from connect import *
from evolve_log import *

logger = GetLogger()

class Host(object):

    def __init__(self, name):
        self.name = name
        self.domain = None
        self.hostname = None
        self.username = None
        self.password = None
        self.make = None
        self.interfaces = [ ]
        self.interfaces_by_name = { }

    def AddInterface(self, name):
        new_intf = Interface(name)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf

    def Connect(self):
        self.hostname = self.name + "." + self.domain
        self.conn = Connect(self.hostname, self.username, self.password)
        if self.conn.Open():
            logger.info("Connection to %s Opened" % self.hostname)


class DebianHost(Host):

    def __init__(self, name):
        super(DebianHost, self).__init__(name)
        self.username = "root"
        self.password = "starent"
        self.ipv4_offset = 256
        self.ipv6_offset = 65536

    def AddInterface(self, name):
        new_intf = LinuxInterface(name)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        new_intf.Bringup(self.conn)
        new_intf.RingSize(self.conn)


class StarOsHost(Host):

    def __init__(self, name):
        super(StarOsHost, self).__init__(name)
        self.username = "staradmin"
        self.password = "starent"
        self.build_server = None
        self.syslog_server = None
        self.crash_server = None
        self.bulkstats_server = None


class Switch(Host):

    def __init__(self, name):
        super(Switch, self).__init__(name)
        self.username = "admin"
        self.password = "starent"


class Parser(object):

    def __init__(self, xml_file):
        self.xml_file = xml_file

    def __AddHosts(self, system, tag):
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
        system.Add(new_host)

    def __AddLinks(self, system, tag):
        bw = tag.attrib['bandwidth']
        nodes = [ ]
        intfs = [ ]
        nodes.append(tag.attrib['node_a'])
        intfs.append(tag.attrib['interface_a'])
        nodes.append(tag.attrib['node_b'])
        intfs.append(tag.attrib['interface_b'])
        # create Interface and add to host
        name = nodes[0] + "-" + nodes[1]
        new_link = Link(name)
        system.AddLink(new_link)
        for index in range(0,2):
            node = system.equipment_by_name[nodes[index]]
            new_link.nodes.append(node)
            node.AddInterface(intfs[index])
            intf = node.interfaces_by_name[intfs[index]] 
            new_link.interfaces.append(intf)
        for next_tag in tag:
            assert next_tag.tag == "ip_network"
            net = Network()
            net.vlan = next_tag.attrib['vlan']
            net.AddIpv4Network(next_tag.attrib['ipv4'])
            net.AddIpv6Network(next_tag.attrib['ipv6'])
            if 'vr' in next_tag.attrib.keys():
                net.vr = next_tag.attrib['vr']
            new_link.AddConnectivity(net)


    def ParseXml(self):
        tree = ET.parse(self.xml_file)
        root_tag = tree.getroot()
        assert root_tag.tag == "system"
        name = root_tag.attrib['name']
        sys = System(name)
        Logger("extensive", "/tmp/evolve.log")

        for next_tag in root_tag:
            if next_tag.tag == "device":
                self.__AddHosts(sys, next_tag)
            elif next_tag.tag == "link":
                self.__AddLinks(sys, next_tag)
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
   
    def Add(self, host):
        self.equipment.append(host)
        self.equipment_by_name[host.name] = host
        host.Connect()

    def AddLink(self, link):
        self.links.append(link)

    def Destroy():
        pass

    def Display(self): 
        for e in self.equipment:
            logger.debug("Host %s" % e.name)
        for l in self.links:
            l.Display()


class Make(object):
 
    def __init__(self, name):
        self.name = name
        self.model = None
        self.type = None


class Link(object):

    def __init__(self, name):
        self.name = name
        self.bandwidth = None
        self.nodes = [ ]
        self.interfaces = [ ]
        self.connections = [ ]

    def AddConnectivity(self, conn):
        self.connections.append(conn)
        for i in range(0, 2):
            node = self.nodes[i]
            intf = self.interfaces[i]
            for c in self.connections:
                intf.Networks(node, c)

    def Display(self):
        logger.debug("Link %s" % self.name)
        for n in self.nodes:
            logger.debug("Node %s" % n.name)
        for n in self.interfaces:
            logger.debug("Interfaces %s" % n.name)
        for c in self.connections:
            c.Display()


class Interface(object):

    def __init__(self, name):
        self.name = name

    def Add(self, network):
        self.networks.append(network)

    def Networks(self, node, net):
        logger.info("Networks bypass")


class LinuxInterface(Interface):

    def __init__(self, name):
        super(LinuxInterface, self).__init__(name)

    def Bringup(self, conn):
        # Migth need to extend as Linux interface
        # 10000 should be set based on 10G Bandwidth
        cmd = [ ]
        cmd.append("ip link set dev " + self.name + " qlen 10000 up")
        # validate
        r = conn.Run(cmd)

    def RingSize(self, conn):
        # Migth need to extend as Linux interface
        cmd = [ ]
        cmd.append("ethtool -g " + self.name)
        r = conn.Run(cmd)
        res1 = self.TvParse(r, "Pre-set maximums", "Current hardware settings", ["RX", "TX"])
        res2 = self.TvParse(r, "Current hardware settings", None, ["RX", "TX"])
        for i in res1.keys():
            if res2[i] != res1[i]:
                cmd = [ ]
                cmd.append("ethtool -G " + self.name + " " + i.lower() + " " + res1[i])
                r = conn.Run(cmd)

    def TvParse(self, input, top, bottom, tags):
        state = "STARTED"
        results = { }
        for line in input.splitlines():
            if state == "STARTED":
                res_obj = re.search(r'([\w\s-]+):', line)
                if res_obj and res_obj.group(1) == top:
                    logger.info("Found top: %s" % res_obj.group(1))
                    state = "TAGS"
            elif state == "TAGS":
                res_obj = re.search(r'([\w\s-]+):\s*([\d]*)', line)
                index = len(results.keys())
                if res_obj and res_obj.group(1) == tags[index]:
                    tag = res_obj.group(1)
                    val = res_obj.group(2)
                    results[tag] = val
                    logger.info("Found tag: tag %s has value %s" % (tag, val))
                    if index == len(tags) - 1:
                        state = "BOTTOM"
            elif state == "BOTTOM":
                res_obj = re.search(r'([\w\s-]+):', line)
                if res_obj and res_obj.group(1) == bottom:
                    logger.info("Found bottom: %s" % res_obj.group(1))
                    break
            else:
                logger.error("Unexpected state: %s" % state)
        return results

    def Networks(self, node, net):
        # check if links exists
        conn = node.conn
        ipv4_offset = node.ipv4_offset
        ipv6_offset = node.ipv6_offset
        cmd = [ ]
        cmd.append("setvr " + net.vr + " ip link show dev " + self.name + "." + net.vlan)
        r = conn.Run(cmd)
        for line in r.splitlines():
            res_obj = re.search(r'Device (.*) does not exist.', line)
            if res_obj:
                cmd = [ ]
                cmd.append("modprobe 8021q")
                cmd.append("setvr " + net.vr + " vconfig add " + self.name + " " + net.vlan)
                cmd.append("setvr " + net.vr + " ip link set dev " + self.name + "." + net.vlan + " up")
                print "cmd: %s" % cmd
                r = conn.Run(cmd)
                print "R: %s" % r
        # check if network exists
        cmd = [ ]
        cmd.append("setvr " + net.vr + " ip addr show dev " + self.name + "." + net.vlan)
        r = conn.Run(cmd)
        found = 0
        ipv4 = net.ipv4
        ipv4.value += (ipv4_offset + 1)
        for line in r.splitlines():
            res_obj = re.search(r'inet ([\d./]+) ', line)
            if res_obj and res_obj.group(1) == str(ipv4.ip) + "/" + str(ipv4.prefixlen):
                logger.info("Found IPv4 %s" % ipv4.ip)
                found = 1
                break
        if not found:
            cmd = [ ]
            cmd.append("setvr " + net.vr + " ip addr add " + str(ipv4.ip) + "/" + str(ipv4.prefixlen) + " dev " + self.name + "." + net.vlan)
            r = conn.Run(cmd)
          

class Network(object):

    def __init__(self):
        self.vlan = None
        self.vr = None
        self.ipv4 = None
        self.ipv6 = None

    def AddIpv4Network(self, net):
        self.ipv4 = netaddr.IPNetwork(net)

    def AddIpv6Network(self, net):
        self.ipv6 = netaddr.IPNetwork(net)

    def Display(self):
        logger.debug("IPv4 - Network: %s, Broadcast: %s, Size %s" % (
            self.ipv4.network, self.ipv4.broadcast, self.ipv4.size))
        logger.debug("IPv6 - Network: %s, Broadcast: %s, Prefix Length: %s" % (
            self.ipv6.network, self.ipv6.broadcast, self.ipv6.prefixlen))
