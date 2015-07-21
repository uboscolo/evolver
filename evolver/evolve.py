import xml.etree.ElementTree as ET
import netaddr
import re
import time
from connect import *
from evolve_log import *
from stargen import *

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

    def PingCheck(self, local_net, remote_net):
        logger.error("Method not implemented")
        assert False

    def RouteCheck(self, local_net, remote_net):
        logger.error("Method not implemented")
        assert False


class DebianHost(Host):

    def __init__(self, name):
        super(DebianHost, self).__init__(name)
        self.username = "root"
        self.password = "starent"

    def AddInterface(self, name, bandwidth):
        new_intf = LinuxInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        new_intf.Bringup(self.conn)
        new_intf.RingSize(self.conn)

    def PingCheck(self, local_net, remote_net):
        logger.debug("Verifying pingability")
        c = self.conn
        cmd_string = "setvr %s ping -c 2 -w 1 %s" % (local_net.vr, remote_net.ipv4.ip)
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
            if res_obj:
                loss = int(res_obj.group(2))
                if loss == 100:
                    logger.debug("Packet loss is too high: %s", loss)
                    return True
        logger.debug("Packet loss within acceptable limits")
        return False


class StarOsHost(Host):

    def __init__(self, name):
        super(StarOsHost, self).__init__(name)
        self.username = "staradmin"
        self.password = "starent"
        self.build_server = None
        self.syslog_server = None
        self.crash_server = None
        self.bulkstats_server = None

    def AddInterface(self, name, bandwidth):
        new_intf = StarOsInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf

    def PingCheck(self, local_net, remote_net):
        c = self.conn
        if not remote_net.ipv4:
            logger.debug("No Ip network")
            return False
        cmd_string = "context %s" % local_net.vr
        r = c.Run([cmd_string])
        cmd_string = "ping %s count 2" % remote_net.ipv4.ip
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
            if res_obj:
                loss = int(res_obj.group(2))
                logger.debug("Packet loss %s", loss)
                if loss == 100:
                    return True
        return False


class Switch(Host):

    def __init__(self, name):
        super(Switch, self).__init__(name)
        self.username = "admin"
        self.password = "starent"

    def AddInterface(self, name, bandwidth):
        new_intf = SwitchInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf

    def Connect(self):
        super(Switch, self).Connect()
        cmd_string = "terminal length 0"
        r = self.conn.Run([cmd_string])

    def PingCheck(self, local_net, remote_net):
        c = self.conn
        if not remote_net.ipv4:
            logger.debug("No Ip network")
            return False
        if not self.RouteCheck(local_net, remote_net):
            logger.debug("Route check failed")
            return True
        cmd_string = "ping %s count 2 timeout 1 vrf %s" % (remote_net.ipv4.ip, local_net.vr)
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ packets received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss', line)
            if res_obj:
                loss = float(res_obj.group(2))
                logger.debug("Packet loss %s", loss)
                if loss == 100:
                    return True
        return False

    def RouteCheck(self, local_net, remote_net):
        attempts = 10
        c = self.conn
        search_string = "%s/%s" % (remote_net.ipv4.network, remote_net.ipv4.prefixlen)
        logger.debug("Looking for a route to %s ..." % search_string)
        for i in range(attempts):
            cmd_string = "show ip route vrf %s" % local_net.vr
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([\d./]+), ubest/mbest', line)
                if res_obj:
                    entry = res_obj.group(1)
                    if entry == search_string:  
                        logger.debug("Found entry for %s" % entry)
                        return True
            time.sleep(3)
        logger.debug("Did not find any entry")
        return False


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
            c = Connectivity()
            assert 'vlan' in next_tag.attrib.keys()
            c.vlan = next_tag.attrib['vlan']
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
                if 'ipv6' in sub_tag.attrib.keys():
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
            net = conn.networks[i]
            intf.AddLink(node, conn, net)
            intf.AddConnectivity(node, conn, net)

    def CheckConnectivity(self):
        node = self.nodes[0]
        for c in self.connections:
            local_net = c.networks[0]  
            remote_net = c.networks[1]  
        if node.PingCheck(local_net, remote_net):
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


class Interface(object):

    def __init__(self, name, bandwidth):
        self.name = name
        self.bandwidth = bandwidth
        self.networks = [ ]
        self.verify_only = False

    def AddConnectivity(self, node, conn, net):
        logger.error("Method not implemented")
        assert False

    def AddLink(self, node, conn, net):
        logger.error("Method not implemented")
        assert False

    def VerifyLink(self, node, conn, net):
        logger.error("Method not implemented")
        assert False


class LinuxInterface(Interface):

    def __init__(self, name, bandwidth):
        super(LinuxInterface, self).__init__(name, bandwidth)

    def AddConnectivity(self, node, conn, net):
        logger.debug("Adding Connectivity")
        c = node.conn
        self.networks.append(net)
        if net.ipv4 and not self.verify_only:
            cmd_string = "setvr %s ip addr add %s/%s dev %s.%s" % (net.vr, 
                net.ipv4.ip, net.ipv4.prefixlen, self.name, conn.vlan)
            r = c.Run([cmd_string])
        if net.ipv6 and not self.verify_only:
            cmd_string = "setvr %s ip -6 addr add %s/%s dev %s.%s" % (net.vr, 
                net.ipv6.ip, net.ipv6.prefixlen, self.name, conn.vlan)
            r = c.Run([cmd_string])

    def AddLink(self, node, conn, net):
        logger.debug("Adding link %s.%s" % (self.name, conn.vlan))
        link_exists = self.VerifyLink(node, conn, net)
        if self.verify_only: 
            if not link_exists:
                logger.error("Link does not exist or is not up, can't proceed")
                assert False
        else:
            c = node.conn
            cmd_string = "setvr %s ip link show dev %s.%s" % (net.vr, self.name, conn.vlan)
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'Device (.*) does not exist.', line)
                if res_obj:
                    logger.debug("Device %s.%s does not exist, creating ..." % (self.name, conn.vlan))
                    cmd_string = "modprobe 8021q"
                    r = c.Run([cmd_string])
            if link_exists:
                cmd_string = "setvr %s vconfig rem %s.%s" % (net.vr, self.name, conn.vlan)
                r = c.Run([cmd_string])
            cmd_string = "setvr %s vconfig add %s %s" % (net.vr, self.name, conn.vlan)
            r = c.Run([cmd_string])
            cmd_string = "setvr %s ip link set dev %s.%s up" % (net.vr, self.name, conn.vlan)
            r = c.Run([cmd_string])

    def Bringup(self, c):
        logger.debug("Verifying if device %s is up" % self.name)
        cmd_string = "ip link show dev %s" % self.name
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Device (.*) does not exist.', line)
            if res_obj:
                logger.error("Device %s doesn't exist" % self.name)
                assert False
        found = False
        cmd_string = "ip link show dev %s up" % self.name
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+: ([\w\d]+): <.*> mtu ([\d]+) .* qlen ([\d]+)', line)
            if res_obj:
                device = res_obj.group(1)
                mtu = res_obj.group(2)
                qlen = res_obj.group(3)
                if device == self.name:
                    found = True
                    logger.debug("Device %s found and up (mtu: %s, qlen: %s)" % (self.name, mtu, qlen))
                if self.bandwidth == "10G" and not qlen == 10000:
                    logger.warning("10Gb/s link, it's preferable to set qlen to 10000, qlen %s" % qlen)
        if not found:
            if not self.verify_only:
                logger.debug("Bringing up link ...")
                if self.bandwidth == "10G":
                    cmd_string = "ip link set dev %s qlen 10000 up" % self.name
                else:
                    cmd_string = "ip link set dev %s up" % self.name
                r = c.Run([cmd_string])
                # validate, check errors
            else:
                logger.error("Device is not up")
                assert False

    def RingSize(self, c):
        logger.debug("Verifying if ring size is set to max")
        cmd_string = "ethtool -g %s" % self.name
        r = c.Run([cmd_string])
        res1 = self.TvParse(r, "Pre-set maximums", "Current hardware settings", ["RX", "TX"])
        res2 = self.TvParse(r, "Current hardware settings", None, ["RX", "TX"])
        if not res1 or not res2:
            logger.warning("Unable to find hardware settings")
            return
        for i in res1.keys():
            if res2[i] != res1[i]:
                logger.warning("hardware settings mismatch, max=%s, current=%s" % (res1[i], res2[i]))
                if not self.verify_only:
                    logger.debug("Changing hardware settings ...")
                    cmd_string = "ethtool -G %s %s %s" % (self.name, i.lower(), res1[i])
                    r = c.Run([cmd_string])
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

    def VerifyLink(self, node, conn, net):
        logger.debug("Verifying if link %s.%s is up" % (self.name, conn.vlan))
        c = node.conn
        cmd_string = "setvr %s ip link show dev %s.%s up" % (net.vr, self.name, conn.vlan)
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'Device (.*) does not exist.', line)
            if res_obj:
                device = res_obj.group(1)
                logger.warning("Device %s doesn't exist" % device)
                return False
        logger.debug("Found link %s.%s is up" % (self.name, conn.vlan))
        return True


class SwitchInterface(Interface):

    def __init__(self, name, bandwidth):
        super(SwitchInterface, self).__init__(name, bandwidth)

    def AddConnectivity(self, node, conn, net):
        if not net.ipv4 and not net.ipv6:
            logger.debug("IP network not specified")
            return 
        c = node.conn
        self.networks.append(net)
        if not self.verify_only:
            cmd_string = "configure terminal"
            r = c.Run([cmd_string])
            cmd_string = "vrf context %s" % net.vr
            r = c.Run([cmd_string])
            cmd_string = "exit"
            r = c.Run([cmd_string])
            cmd_string = "no interface vlan %s" % conn.vlan
            r = c.Run([cmd_string])
            cmd_string = "interface vlan %s" % conn.vlan
            r = c.Run([cmd_string])
            cmd_string = "no shutdown"
            r = c.Run([cmd_string])
            cmd_string = "vrf member %s" % net.vr 
            r = c.Run([cmd_string])
            if net.ipv4:
                cmd_string = "ip address %s/%s" % (net.ipv4.ip, net.ipv4.prefixlen)
                r = c.Run([cmd_string])
            if net.ipv6:
                cmd_string = "ipv6 address %s/%s" % (net.ipv6.ip, net.ipv6.prefixlen)
                r = c.Run([cmd_string])
            cmd_string = "end"
            r = c.Run([cmd_string])

    def AddLink(self, node, conn, net):
        link_exists = self.VerifyLink(node, conn, net)
        if self.verify_only: 
            if not link_exists:
                logger.error("Interface or port-channel do not exist")
                assert False
        else:
            c = node.conn
            if conn.port_channel:
                cmd_string = "configure terminal"
                r = c.Run([cmd_string])
                cmd_string = "feature lacp"
                r = c.Run([cmd_string])
                cmd_string = "interface port-channel %s" % conn.port_channel
                r = c.Run([cmd_string])
                if not link_exists:
                    logger.debug("Port channel %s not found" % conn.port_channel)
                    cmd_string = "switchport mode trunk"
                    r = c.Run([cmd_string])
                    logger.debug("Looking if all vlans 1-4094 are allowed ...")
                    cmd_string = "show interface port-channel %s switchport | grep \"Trunking VLANs Allowed\"" % conn.port_channel
                    r = c.Run([cmd_string])
                    for line in r.splitlines():
                        res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
                        if res_obj:
                            logger.debug("All vlans 1-4094 are allowed, changing to none")
                            cmd_string = "switchport trunk allowed vlan none"
                            r = c.Run([cmd_string])
                cmd_string = "end"
                r = c.Run([cmd_string])
            # configure the interface
            cmd_string = "configure terminal"
            r = c.Run([cmd_string])
            cmd_string = "interface ethernet %s" % self.name
            r = c.Run([cmd_string])
            # if not trunk, enable it
            logger.debug("Looking if mode is trunk ...")
            cmd_string = "show interface ethernet %s switchport | grep \"Operational Mode\"" % self.name
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'Operational Mode: ([\w]+)', line)
                if res_obj:
                    mode = res_obj.group(1)
                    if not (mode == "trunk"):
                        logger.debug("Mode is not trunk: %s, changing to trunk" % mode)
                        cmd_string = "switchport mode trunk"
                        r = c.Run([cmd_string])
            logger.debug("Looking if all vlans 1-4094 are allowed ...")
            cmd_string = "show interface ethernet %s switchport | grep \"Trunking VLANs Allowed\"" % self.name
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
                if res_obj:
                    logger.debug("All vlans 1-4094 are allowed, changing to none")
                    cmd_string = "switchport trunk allowed vlan none"
                    r = c.Run([cmd_string])
            # Add the vlans
            if conn.port_channel:
                cmd_string = "channel-group %s force mode active" % conn.port_channel
                r = c.Run([cmd_string])
                cmd_string = "interface port-channel %s" % conn.port_channel
                r = c.Run([cmd_string])
            cmd_string = "switchport trunk allowed vlan add %s" % conn.vlan
            r = c.Run([cmd_string])
            cmd_string = "end"
            r = c.Run([cmd_string])

    def VerifyLink(self, node, conn, net):
        logger.debug("Looking for vlan %s ..." % conn.vlan)
        c = node.conn
        cmd_string = "show vlan id %s" % conn.vlan
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'VLAN ([\d]+) not found in current VLAN database', line)
            if res_obj:
                logger.debug("Vlan %s not found" % conn.vlan)
                if self.verify_only:
                    logger.error("Did not find vlan, can't proceed")
                    assert False
                logger.debug("Adding vlan %s", conn.vlan)
                cmd_string = "configure terminal"
                r = c.Run([cmd_string])
                cmd_string = "vlan %s" % conn.vlan
                r = c.Run([cmd_string])
                cmd_string = "exit"
                r = c.Run([cmd_string])
        # find interface, then port channel
        found = False
        logger.debug("Looking for interface %s ..." % self.name)
        cmd_string = "show interface ethernet %s brief" % self.name
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'([\d/\w]+) ', line)
            if res_obj:
                intf = res_obj.group(1)
                target_intf = "Eth%s" % self.name
                if intf == target_intf:
                    logger.debug("Found interface %s" % intf)
                    found = True
                    break
        if found and conn.port_channel:
            found = False
            logger.debug("Looking for port-channel %s ..." % conn.port_channel)
            cmd_string = "show port-channel summary"
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([\d]+).*Po([\d]+)', line)
                if res_obj:
                    po = res_obj.group(1)
                    if po == conn.port_channel:
                        logger.debug("Found port channel %s" % po)
                        found = True
                        break
        return found


class StarOsInterface(Interface):

    def __init__(self, name, bandwidth):
        super(StarOsInterface, self).__init__(name, bandwidth)

    def AddLink(self, node, conn, net):
        if conn.port_channel and not (net.ipv4 or net.ipv6):
            logger.debug("Secondary member of a port channel")
            return
        # check if links exists, fail otherwise
        link_exists =  False       
        c = node.conn
        cmd_string = "context %s" % (net.vr)
        r = c.Run([cmd_string])
        cmd_string = "show ip interface | grep \"Bound to %s\"" % self.name
        r = c.Run([cmd_string])
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
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'IP State:.*UP', line)
            if res_obj:
                logger.debug("Interface %s found, status is UP" % new_intf)
                link_exists =  True
        # verify
        if not link_exists:
            logger.error("Interface %s not found, or status is DOWN" % self.name)
            assert False
 
    def AddConnectivity(self, node, conn, net):
        # check if network exists, fail otherwise
        c = node.conn


class Network(object):

     def __init__(self):
        self.vr = None
        self.ipv4 = None
        self.ipv6 = None

     def AddIpv4(self, addr):
        self.ipv4 = netaddr.IPNetwork(addr)
 
     def AddIpv6(self, addr):
        self.ipv6 = netaddr.IPNetwork(addr)

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
        self.networks[0].AddIpv4(nets[0])
        self.networks[1].AddIpv4(nets[1])

    def AddVrs(self, vrs):
        assert len(vrs) == 2
        self.networks[0].vr = vrs[0]
        self.networks[1].vr = vrs[1]

    def Display(self):
        for n in self.networks:
            n.Display()
