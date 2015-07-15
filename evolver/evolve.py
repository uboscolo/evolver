import xml.etree.ElementTree as ET
import netaddr
import re
import time
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

    def AddInterface(self, name, bandwidth):
        logger.error("Method not implemented")
        assert False

    def Connect(self):
        self.hostname = self.name + "." + self.domain
        self.conn = Connect(self.hostname, self.username, self.password)
        if self.conn.Open():
            logger.info("Connected to %s Opened" % self.hostname)


class DebianHost(Host):

    def __init__(self, name):
        super(DebianHost, self).__init__(name)
        self.username = "root"
        self.password = "starent"
        self.ipv4_offset = 0
        self.ipv6_offset = 0

    def AddInterface(self, name, bandwidth):
        new_intf = LinuxInterface(name, bandwidth)
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
        self.ipv4_offset = 0
        self.ipv6_offset = 0

    def AddInterface(self, name, bandwidth):
        new_intf = StarOsInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf


class Switch(Host):

    def __init__(self, name):
        super(Switch, self).__init__(name)
        self.username = "admin"
        self.password = "starent"
        self.ipv4_offset = 128
        self.ipv6_offset = 256

    def AddInterface(self, name, bandwidth):
        new_intf = SwitchInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf


class Parser(object):

    def __init__(self, xml_file):
        self.xml_file = xml_file

    def __AddHosts(self, system, tag):
        # verify these 3 tags are present
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
        system.AddEquipment(new_host)

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
            node.AddInterface(intfs[index], bw)
            intf = node.interfaces_by_name[intfs[index]] 
            new_link.interfaces.append(intf)
        for next_tag in tag:
            assert next_tag.tag == "connectivity"
            net = Network()
            net.vlan = next_tag.attrib['vlan']
            if 'ipv4' in next_tag.attrib.keys():
                net.AddIpv4Network(next_tag.attrib['ipv4'])
            if 'ipv6' in next_tag.attrib.keys():
                net.AddIpv6Network(next_tag.attrib['ipv6'])
            if 'vr' in next_tag.attrib.keys():
                net.vr = next_tag.attrib['vr']
            if 'port_channel' in next_tag.attrib.keys():
                net.port_channel = next_tag.attrib['port_channel']
            new_link.AddConnectivity(net)

    def ParseXml(self):
        tree = ET.parse(self.xml_file)
        root_tag = tree.getroot()
        assert root_tag.tag == "system"
        name = root_tag.attrib['name']
        sys = System(name)

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
   
    def AddEquipment(self, host):
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

    def CheckConnectivity(self): 
        for l in self.links:
            l.CheckConnectivity()


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
            intf.AddLink(node, conn)
            intf.AddConnectivity(node, conn)

    def CheckConnectivity(self):
        node = self.nodes[0]
        intf = self.interfaces[0]
        remote_intf = self.interfaces[1]
        if intf.PingCheck(node, remote_intf):
            logger.error("Ping check failed")
            raise
 
    def Display(self):
        logger.debug("Link %s" % self.name)
        for n in self.nodes:
            logger.debug("Node %s" % n.name)
        for n in self.interfaces:
            logger.debug("Interfaces %s" % n.name)
        for c in self.connections:
            c.Display()


class Interface(object):

    def __init__(self, name, bandwidth):
        self.name = name
        self.bandwidth = bandwidth
        self.networks = [ ]

    def AddLink(self, node, net):
        logger.error("Method not implemented")
        raise

    def AddConnectivity(self, node, net):
        logger.error("Method not implemented")
        raise

    def PingCheck(self, node, remote_intf):
        logger.error("Method not implemented")
        raise


class LinuxInterface(Interface):

    def __init__(self, name, bandwidth):
        super(LinuxInterface, self).__init__(name, bandwidth)

    def Bringup(self, conn):
        if self.bandwidth == "10G":
            cmd_string = "ip link set dev %s qlen 10000 up" % self.name
        else:
            cmd_string = "ip link set dev %s up" % self.name
        r = conn.Run([cmd_string])
        # validate, check errors

    def RingSize(self, conn):
        cmd_string = "ethtool -g %s" % self.name
        r = conn.Run([cmd_string])
        # Validation
        res1 = self.TvParse(r, "Pre-set maximums", "Current hardware settings", ["RX", "TX"])
        res2 = self.TvParse(r, "Current hardware settings", None, ["RX", "TX"])
        for i in res1.keys():
            if res2[i] != res1[i]:
                cmd_string = "ethtool -G %s %s %s" % (self.name, i.lower(), res1[i])
                r = conn.Run([cmd_string])
                # Validation needed

    def TvParse(self, input, top, bottom, tags):
        # create a Parser object that can be called
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

    def AddLink(self, node, net):
        # check if links exists, create otherwise
        link_exists = True        
        conn = node.conn
        cmd_string = "setvr %s ip link show dev %s.%s" % (net.vr, self.name, net.vlan)
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Device (.*) does not exist.', line)
            if res_obj:
                link_exists = False
                cmd_string = "modprobe 8021q"
                r = conn.Run([cmd_string])
        if link_exists:
            cmd_string = "setvr %s vconfig rem %s.%s" % (net.vr, self.name, net.vlan)
            r = conn.Run([cmd_string])
        cmd_string = "setvr %s vconfig add %s %s" % (net.vr, self.name, net.vlan)
        r = conn.Run([cmd_string])
        cmd_string = "setvr %s ip link set dev %s.%s up" % (net.vr, self.name, net.vlan)
        r = conn.Run([cmd_string])

    def AddConnectivity(self, node, net):
        conn = node.conn
        new_net = Network()
        self.networks.append(new_net)
        new_net.vr = net.vr
        new_net.vlan = net.vlan
        if net.ipv4:
            ipv4_offset = node.ipv4_offset
            new_net.AddIpv4Network(net.ipv4.ipv4())
            new_net.ipv4.value += (ipv4_offset + 1)
            cmd_string = "setvr %s ip addr add %s/%s dev %s.%s" % (new_net.vr, 
                new_net.ipv4.ip, new_net.ipv4.prefixlen, self.name, new_net.vlan)
            r = conn.Run([cmd_string])
        if net.ipv4:
            ipv6_offset = node.ipv6_offset
            new_net.AddIpv6Network(net.ipv6.ipv6())
            new_net.ipv6.__iadd__(ipv6_offset + 1)
            cmd_string = "setvr %s ip -6 addr add %s/%s dev %s.%s" % (new_net.vr, 
                new_net.ipv6.ip, new_net.ipv6.prefixlen, self.name, new_net.vlan)
            r = conn.Run([cmd_string])

    def PingCheck(self, node, remote_intf):
        conn = node.conn
        for net in remote_intf.networks:
            cmd_string = "ping -c 2 -w 1 %s" % net.ipv4.ip
            r = conn.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
                if res_obj:
                    loss = int(res_obj.group(2))
                    logger.debug("Packet loss %s", loss)
                    if loss == 100:
                        return True
        return False

    def VerifyLink(self, node, net):
        conn = node.conn
        cmd_string = "setvr %s ip link show dev %s.%s" % (net.vr, self.name, net.vlan)
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Device (.*) does not exist.', line)
            if res_obj:
                device = res_obj.group(1)
                logger.warning("Device %s doesn't exist" % device)
                return False
        return True


class SwitchInterface(Interface):

    def __init__(self, name, bandwidth):
        super(SwitchInterface, self).__init__(name, bandwidth)

    def AddLink(self, node, net):
        conn = node.conn
        # check if vlan exists, create otherwise
        logger.debug("Looking for vlan %s ..." % net.vlan)
        cmd_string = "show vlan id %s" % net.vlan
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'VLAN ([\d]+) not found in current VLAN database', line)
            if res_obj:
                logger.debug("Vlan %s not found" % net.vlan)
                cmd_string = "configure terminal"
                r = conn.Run([cmd_string])
                cmd_string = "vlan %s" % net.vlan
                r = conn.Run([cmd_string])
                cmd_string = "exit"
                r = conn.Run([cmd_string])
        # create the port channel, if not there
        if net.port_channel:
            found = False
            logger.debug("Looking for port-channel %s ..." % net.port_channel)
            cmd_string = "show port-channel summary"
            r = conn.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([\d]+).*Po([\d]+)', line)
                if res_obj:
                    po = res_obj.group(1)
                    if po == net.port_channel:
                        logger.debug("Found port channel %s" % po)
                        found = True
            cmd_string = "configure terminal"
            r = conn.Run([cmd_string])
            cmd_string = "feature lacp"
            r = conn.Run([cmd_string])
            cmd_string = "interface port-channel %s" % net.port_channel
            r = conn.Run([cmd_string])
            if not found:
                logger.debug("Port channel %s not found" % net.port_channel)
                cmd_string = "switchport mode trunk"
                r = conn.Run([cmd_string])
                logger.debug("Looking if all vlans 1-4094 are allowed ...")
                cmd_string = "show interface port-channel %s switchport | grep \"Trunking VLANs Allowed\"" % net.port_channel
                r = conn.Run([cmd_string])
                for line in r.splitlines():
                    res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
                    if res_obj:
                        logger.debug("All vlans 1-4094 are allowed, changing to none")
                        cmd_string = "switchport trunk allowed vlan none"
                        r = conn.Run([cmd_string])
            cmd_string = "end"
            r = conn.Run([cmd_string])
        # configure the interface
        cmd_string = "configure terminal"
        r = conn.Run([cmd_string])
        cmd_string = "interface ethernet %s" % self.name
        r = conn.Run([cmd_string])
        # if not trunk, enable it
        logger.debug("Looking if mode is trunk ...")
        cmd_string = "show interface ethernet %s switchport | grep \"Operational Mode\"" % self.name
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Operational Mode: ([\w]+)', line)
            if res_obj:
                mode = res_obj.group(1)
                if not (mode == "trunk"):
                    logger.debug("Mode is not trunk: %s, changing to trunk" % mode)
                    cmd_string = "switchport mode trunk"
                    r = conn.Run([cmd_string])
        logger.debug("Looking if all vlans 1-4094 are allowed ...")
        cmd_string = "show interface ethernet %s switchport | grep \"Trunking VLANs Allowed\"" % self.name
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
            if res_obj:
                logger.debug("All vlans 1-4094 are allowed, changing to none")
                cmd_string = "switchport trunk allowed vlan none"
                r = conn.Run([cmd_string])
        # Add the vlans
        if net.port_channel:
            cmd_string = "channel-group %s force mode active" % net.port_channel
            r = conn.Run([cmd_string])
            cmd_string = "interface port-channel %s" % net.port_channel
            r = conn.Run([cmd_string])
        cmd_string = "switchport trunk allowed vlan add %s" % net.vlan
        r = conn.Run([cmd_string])
        cmd_string = "end"
        r = conn.Run([cmd_string])

    def AddConnectivity(self, node, net):
        if not net.ipv4 and not net.ipv6:
            logger.debug("IP network not specified")
            return 
        conn = node.conn
        new_net = Network()
        self.networks.append(new_net)
        new_net.vlan = net.vlan
        new_net.vr = net.vr
        cmd_string = "configure terminal"
        r = conn.Run([cmd_string])
        cmd_string = "vrf context %s" % new_net.vr
        r = conn.Run([cmd_string])
        cmd_string = "exit"
        r = conn.Run([cmd_string])
        cmd_string = "no interface vlan %s" % new_net.vlan
        r = conn.Run([cmd_string])
        cmd_string = "interface vlan %s" % new_net.vlan
        r = conn.Run([cmd_string])
        cmd_string = "no shutdown"
        r = conn.Run([cmd_string])
        cmd_string = "vrf member %s" % new_net.vr 
        r = conn.Run([cmd_string])
        if net.ipv4:
            ipv4_offset = node.ipv4_offset
            new_net.AddIpv4Network(net.ipv4.ipv4())
            new_net.ipv4.value += (ipv4_offset + 1)
            cmd_string = "ip address %s/%s" % (new_net.ipv4.ip, new_net.ipv4.prefixlen)
            r = conn.Run([cmd_string])
        if net.ipv6:
            ipv6_offset = node.ipv6_offset
            new_net.AddIpv6Network(net.ipv6.ipv6())
            new_net.ipv6.__iadd__(ipv6_offset + 1)
            cmd_string = "ipv6 address %s/%s" % (new_net.ipv6.ip, new_net.ipv6.prefixlen)
            r = conn.Run([cmd_string])
        cmd_string = "end"
        r = conn.Run([cmd_string])

    def PingCheck(self, node, remote_intf):
        conn = node.conn
        for net in remote_intf.networks:
            if not net.ipv4:
                logger.debug("No Ip network")
                return False
            if not self.RouteCheck(node, net):
                logger.debug("Route check failed")
                return False
            cmd_string = "ping %s count 2 timeout 1 vrf %s" % (net.ipv4.ip, net.vr)
            r = conn.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ packets received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss', line)
                if res_obj:
                    loss = float(res_obj.group(2))
                    logger.debug("Packet loss %s", loss)
                    if loss == 100:
                        return True
        return False

    def RouteCheck(self, node, net):
        attempts = 3
        conn = node.conn
        for i in range(attempts):
            cmd_string = "show ip route vrf %s" % net.vr
            r = conn.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([\d./]+), ubest/mbest', line)
                if res_obj:
                    entry = res_obj.group(1)
                    if entry == net.ipv4.network:  
                        logger.debug("Found entry for %s" % entry)
                        return True
            time.sleep(3)
        logger.debug("Did not find any entry")
        return False


class StarOsInterface(Interface):

    def __init__(self, name, bandwidth):
        super(StarOsInterface, self).__init__(name, bandwidth)

    def AddLink(self, node, net):
        if net.port_channel and not (net.ipv4 or net.ipv6):
            logger.debug("Secondary member of a port channel")
            return
        # check if links exists, fail otherwise
        link_exists =  False       
        conn = node.conn
        cmd_string = "context %s" % (net.vr)
        r = conn.Run([cmd_string])
        cmd_string = "show ip interface | grep \"Bound to %s\"" % self.name
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'IP State:.*UP', line)
            if res_obj:
                logger.debug("Interface %s found, status is UP" % self.name)
                link_exists =  True
        if node.make.model == "ASR5500":
            card, port = self.name.split("/")
            if card == "5":
                new_intf = "6/" + port
            elif card == "6":
                new_intf = "5/" + port
            else:
                logger.error("Unexpected interface" % self.name)
                assert False
        cmd_string = "show ip interface | grep \"Bound to %s\"" % new_intf
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'IP State:.*UP', line)
            if res_obj:
                logger.debug("Interface %s found, status is UP" % new_intf)
                link_exists =  True
        # verify
        if not link_exists:
            logger.error("Interface %s not found, or status is DOWN" % self.name)
            raise
 
    def AddConnectivity(self, node, net):
        # check if network exists, fail otherwise
        conn = node.conn
        ipv4_offset = node.ipv4_offset
        ipv6_offset = node.ipv6_offset
        ipv4 = net.ipv4

    def PingCheck(self, node, remote_intf):
        conn = node.conn
        for net in remote_intf.networks:
            if not net.ipv4:
                logger.debug("No Ip network")
                return False
            cmd_string = "context %s" % net.vr
            r = conn.Run([cmd_string])
            cmd_string = "ping %s count 2" % net.ipv4.ip
            r = conn.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
                if res_obj:
                    loss = int(res_obj.group(2))
                    logger.debug("Packet loss %s", loss)
                    if loss == 100:
                        return True
        return False
 

class Network(object):

    def __init__(self):
        self.vlan = None
        self.vr = None
        self.port_channel = None
        self.ipv4 = None
        self.ipv6 = None

    def AddIpv4Network(self, net):
        self.ipv4 = netaddr.IPNetwork(net)

    def AddIpv6Network(self, net):
        self.ipv6 = netaddr.IPNetwork(net)

    def Display(self):
        if self.ipv4:
            logger.debug("IPv4 - Network: %s, Broadcast: %s, Size %s" % (
                self.ipv4.network, self.ipv4.broadcast, self.ipv4.size))
        if self.ipv6:
            logger.debug("IPv6 - Network: %s, Broadcast: %s, Prefix Length: %s" % (
                self.ipv6.network, self.ipv6.broadcast, self.ipv6.prefixlen))
