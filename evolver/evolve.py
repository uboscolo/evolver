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
        self.loopbacks = [ ]
        self.interfaces = [ ]
        self.interfaces_by_name = { }
        self.verify_only = True

    def AddInterface(self, name, bandwidth):
        logger.error("Method not implemented")
        assert False

    def AddLoopback(self, addr, vr, num=1):
        logger.error("Method not implemented")
        assert False

    def AddRoute(self, net_from, net_to, net_via, ver=4):
        logger.error("Method not implemented")
        assert False

    def Connect(self):
        self.hostname = self.name + "." + self.domain
        self.conn = Connect(self.hostname, self.username, self.password)
        if self.conn.Open():
            logger.info("Connected to %s Opened" % self.hostname)

    def PingCheck(self, local_net, remote_net, ver=4):
        logger.error("Method not implemented")
        assert False

    def RouteCheck(self, local_net, remote_net, ver=4):
        logger.error("Method not implemented")
        assert False


class DebianHost(Host):

    def __init__(self, name):
        super(DebianHost, self).__init__(name)
        self.username = "root"
        self.password = "starent"

    def AddLoopback(self, addr, vr, num=1):
        for l in range(num):
            logger.debug("Adding loopback interface")
            ip = netaddr.IPNetwork(addr)
            ip.__iadd__(l)
            if ip.version == 4 and not ip.prefixlen == 32:
                logger.error("Not a loopback address %s" % ip)
                return
            if ip.version == 6 and not ip.prefixlen == 128:
                logger.error("Not a loopback address %s" % ip)
                return
            lb = Loopback()
            lb.vr = vr
            lb.addr = ip
            self.loopbacks.append(lb)
            # check if loopback exists
            found = False
            c = self.conn
            cmd_string = "setvr %s ip addr show | grep %s" % (vr, ip)
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'[\s]+inet6? ([A-Fa-f\d.:/]+)', line)
                if res_obj:
                    res = netaddr.IPNetwork(res_obj.group(1))
                    logger.debug("Loopback target: %s", res)
                    if res == ip:
                        logger.debug("Loopback found: %s", res)
                        found = True
                        break
            if not found and not self.verify_only:
                cmd_string = "setvr %s ip addr add %s dev lo" % (vr, ip)
                r = c.Run([cmd_string])
        
    def AddInterface(self, name, bandwidth):
        new_intf = LinuxInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        new_intf.verify_only = self.verify_only
        new_intf.Bringup(self.conn)
        new_intf.RingSize(self.conn)

    def AddRoute(self, net_from, net_to, net_via, ver=4):
        c = self.conn
        # check route
        if ver == 4:
            if not net_to.ipv4:
                logger.warning("No ipv4 network")
                return
            cmd_string = "setvr %s ip route show | grep %s" % (net_from.vr, net_to.ipv4.ip)
            to_target = net_to.ipv4.ip
            via_target = net_via.ipv4.ip
            route_string = "setvr %s ip route add %s via %s" % (net_from.vr, net_to.ipv4, net_via.ipv4.ip)
        elif ver == 6:
            if not net_to.ipv6:
                logger.warning("No ipv6 network")
                return
            cmd_string = "setvr %s ip -6 route show | grep %s" % (net_from.vr, net_to.ipv6.ip)
            to_target = net_to.ipv6.ip
            via_target = net_via.ipv6.ip
            route_string = "setvr %s ip -6 route add %s via %s" % (net_from.vr, net_to.ipv6, net_via.ipv6.ip)
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        found = False
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'([A-Fa-f\d.:/]+) via ([A-Fa-f\d.:]+)', line)
            if res_obj:
                to = netaddr.IPNetwork(res_obj.group(1)).ip
                via = netaddr.IPNetwork(res_obj.group(2)).ip
                if to == to_target and via == via_target:
                    logger.debug("Route to %s via %s found" % (to, via))
                    found = True
                    break
        # create route
        if not found:
            if self.verify_only:
                logger.error("Route not found, can't proceed")
                assert False
            r = c.Run([route_string])

    def PingCheck(self, local_net, remote_net, ver=4):
        logger.debug("Verifying pingability")
        c = self.conn
        retval = True
        if ver == 4:
            if not remote_net.ipv4 or remote_net.ipv4.ip == remote_net.ipv4.network:
                logger.debug("No ipv4 network")
                return False
            cmd_string = "setvr %s ping -c 2 -w 1 -i 0.5 %s -I %s" % (local_net.vr, remote_net.ipv4.ip, local_net.ipv4.ip)
        elif ver == 6:
            if not remote_net.ipv6 or remote_net.ipv6.ip == remote_net.ipv6.network:
                logger.debug("No ipv6 network")
                return False
            cmd_string = "setvr %s ping6 -c 2 -w 1 %s -i 0.5 -I %s" % (local_net.vr, remote_net.ipv6.ip, local_net.ipv6.ip)
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
            if res_obj:
                loss = int(res_obj.group(2))
                if loss < 100:
                    logger.debug("Packet loss is within tolerance: %s", loss)
                    retval = False
                    break
        return retval


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
        if not self.verify_only:
            new_intf.verify_only = False

    def AddLoopback(self, addr, vr, num=1):
        for l in range(num):
            logger.debug("Checking for loopback ...")

    def AddRoute(self, net_from, net_to, net_via, ver=4):
        # check route
        c = self.conn
        cmd_string = "context %s" % net_from.vr
        r = c.Run([cmd_string])
        if ver == 4:
            if not net_to.ipv4:
                logger.warning("No ipv4 network")
                return
            cmd_string = "show ip route | grep %s" % net_to.ipv4.ip
            to_target = net_to.ipv4
            via_target = net_via.ipv4.ip
        elif ver == 6:
            if not net_to.ipv6:
                logger.warning("No ipv6 network")
                return
            cmd_string = "show ipv6 route | grep %s" % net_to.ipv6.ip
            to_target = net_to.ipv6
            via_target = net_via.ipv6.ip
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        found = False
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'\*([A-Fa-f\d.:/]+)[\s]+([A-Fa-f\d.:]+)', line)
            if res_obj:
                to = netaddr.IPNetwork(res_obj.group(1))
                via = netaddr.IPNetwork(res_obj.group(2)).ip
                if to == to_target and via == via_target:
                    logger.debug("Route to %s via %s found" % (to, via))
                    found = True
                    break
        # create route
        if not found:
            logger.error("Route not found, can't proceed")
            assert False

    def PingCheck(self, local_net, remote_net, ver=4):
        logger.debug("Verifying pingability")
        c = self.conn
        if ver == 4:
            if not remote_net.ipv4 or remote_net.ipv4.ip == remote_net.ipv4.network:
                logger.debug("No ipv4 network")
                return False
            ping_string = "ping %s count 2 src %s" % (remote_net.ipv4.ip, local_net.ipv4.ip)
        elif ver == 6:
            if not remote_net.ipv6 or remote_net.ipv6.ip == remote_net.ipv6.network:
                logger.debug("No ipv6 network")
                return False
            ping_string = "ping6 %s count 2 src %s" % (remote_net.ipv6.ip, local_net.ipv6.ip)
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        cmd_string = "context %s" % local_net.vr
        r = c.Run([cmd_string])
        retval = True
        r = c.Run([ping_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss, (time [\d\w]+)?', line)
            if res_obj:
                loss = int(res_obj.group(2))
                if loss < 100:
                    logger.debug("Packet loss is within tolerance: %s", loss)
                    retval = False
                    break
        return retval


class Switch(Host):

    def __init__(self, name):
        super(Switch, self).__init__(name)
        self.username = "admin"
        self.password = "starent"

    def AddInterface(self, name, bandwidth):
        new_intf = SwitchInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        if not self.verify_only:
            new_intf.verify_only = False

    def AddLoopback(self, addr, vr, num=1):
        for l in range(num):
            logger.debug("Checking for loopback ...")
            ip = netaddr.IPNetwork(addr)
            ip.__iadd__(l)
            if ip.version == 4 and  not ip.prefixlen == 32:
                logger.error("Not a loopback address %s" % ip)
                return
            if ip.version == 6 and  not ip.prefixlen == 128:
                logger.error("Not a loopback address %s" % ip)
                return
            lb = Loopback()
            lb.vr = vr
            lb.addr = ip
            self.loopbacks.append(lb)
            # check if loopback exists
            found = False
            c = self.conn
            cmd_string = "show interface | grep %s" % ip
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'  Internet Address is ([A-Fa-f\d.:/]+)', line)
                if res_obj:
                    res = netaddr.IPNetwork(res_obj.group(1))
                    if res == ip:
                        logger.debug("Loopback found: %s", res)
                        found = True
                        break
            if not found and not self.verify_only:
                # assign mumber to interface
                unavail_num = [ ]
                if_num = None
                cmd_string = "show interface brief | grep Lo"
                r = c.Run([cmd_string])
                for line in r.splitlines():
                    res_obj = re.search(r'Lo([\d]+)', line)
                    if res_obj:
                        num = int(res_obj.group(1))
                        unavail_num.append(num) 
                for i in range(1, 1024):
                    if not i in unavail_num:
                        logger.debug("Next available loopback is %s" % i)
                        if_num = i
                        break
                if not if_num:
                    logger.error("Ran out of loopback interfaces (%s)" % i)
                    assert False
                cmd_string = "configure terminal"
                r = c.Run([cmd_string])
                cmd_string = "interface loopback %s" % if_num
                r = c.Run([cmd_string])
                cmd_string = "vrf member %s" % vr
                r = c.Run([cmd_string])
                cmd_string = "ip address %s" % ip
                r = c.Run([cmd_string])
                cmd_string = "end"
                r = c.Run([cmd_string])

    def AddRoute(self, net_from, net_to, net_via, ver=4):
        # check route
        c = self.conn
        if ver == 4:
            if not net_to.ipv4:
                logger.warning("No ipv4 network")
                return
            cmd_string = "show ip route vrf %s | grep -A 1 %s" % (net_from.vr, net_to.ipv4)
            to_target = net_to.ipv4
            via_target = net_via.ipv4.ip
        elif ver == 6:
            if not net_to.ipv6:
                logger.warning("No ipv6 network")
                return
            cmd_string = "show ipv6 route vrf %s | grep -A 1 %s" % (net_from.vr, net_to.ipv6)
            to_target = net_to.ipv6
            via_target = net_via.ipv6.ip
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        found = False
        to = None
        via = None
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj1 = re.search(r'([A-Fa-f\d.:/]+), ubest/mbest', line)
            res_obj2 = re.search(r'[\s]+\*via ([A-Fa-f\d.:]+),', line)
            if res_obj1:
                to = netaddr.IPNetwork(res_obj1.group(1))
            if res_obj2:
                via = netaddr.IPNetwork(res_obj2.group(1)).ip
            if to == to_target and via == via_target:
                logger.debug("Route to %s via %s found" % (to, via))
                found = True
                break
        # create route
        if not found:
            assert False

    def Connect(self):
        super(Switch, self).Connect()
        cmd_string = "terminal length 0"
        r = self.conn.Run([cmd_string])

    def PingCheck(self, local_net, remote_net, ver=4):
        c = self.conn
        if ver == 4:
            if not remote_net.ipv4 or remote_net.ipv4.ip == remote_net.ipv4.network:
                logger.debug("No ipv4 network")
                return False
            cmd_string = "ping %s count 2 timeout 1 vrf %s source %s" % (remote_net.ipv4.ip, local_net.vr, local_net.ipv4.ip)
        elif ver == 6:
            if not remote_net.ipv6 or remote_net.ipv6.ip == remote_net.ipv6.network:
                logger.debug("No ipv4 network")
                return False
            cmd_string = "ping6 %s count 2 timeout 1 vrf %s" % (remote_net.ipv6.ip, local_net.vr)
        else:
            logger.error("Unexpected ip version %s" % ver)
            assert False
        if not self.RouteCheck(local_net, remote_net, ver):
            logger.debug("Route check failed")
            return True
        retval = True
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'[\d]+ packets transmitted, [\d]+ packets received,( [\d+]+ errors ,)? ([\d.]+)\% packet loss', line)
            if res_obj:
                loss = float(res_obj.group(2))
                if loss < 100:
                    logger.debug("Packet loss is within tolerance: %s", loss)
                    retval = False
                    break
        return retval

    def RouteCheck(self, local_net, remote_net, ver=4):
        attempts = 10
        c = self.conn
        if ver == 4: 
            search_string = "%s/%s" % (remote_net.ipv4.network, remote_net.ipv4.prefixlen)
            cmd_string = "show ip route vrf %s | grep %s" % (local_net.vr, search_string)
        elif ver == 6: 
            search_string = "%s/%s" % (remote_net.ipv6.network, remote_net.ipv6.prefixlen)
            cmd_string = "show ipv6 route vrf %s | grep %s" % (local_net.vr, search_string)
        else:
            logger.error("Unexpected version: %s" % ver)
            assert False
        logger.debug("Looking for a route to %s ..." % search_string)
        for i in range(attempts):
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([A-Fa-f\d.:/]+), ubest/mbest', line)
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
        logger.debug("Adding connectivity vlan %s" % conn.vlan)
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


class Interface(object):

    def __init__(self, name, bandwidth):
        self.name = name
        self.bandwidth = bandwidth
        self.networks = [ ]
        self.verify_only = True

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
                    logger.debug("Device %s found and up (mtu: %s, qlen: %s)" % (self.name, mtu, qlen))
                if self.bandwidth == "10G" and not qlen == "10000":
                    logger.warning("10Gb/s link (%s), it's preferable to set qlen to 10000, qlen %s" % (self.bandwidth, qlen))
                    found = True
                    break
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
        logger.debug("Vlan %s configured" % conn.vlan)
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
        logger.debug("Checking if link exists %s" % self.name)
        if conn.port_channel and not (net.ipv4 or net.ipv6):
            logger.debug("Secondary member of a port channel")
            return
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

     def AddIpv4(self, addr, offset=0):
        self.ipv4 = netaddr.IPNetwork(addr)
        logger.debug("IP: %s" % self.ipv4.ip)
        offset <<= (32 - self.ipv4.prefixlen)
        self.ipv4.ip.__iadd__(offset)
        logger.debug("IP: %s, offset: %s" % (self.ipv4.ip, offset))
 
     def AddIpv6(self, addr, offset=0):
        self.ipv6 = netaddr.IPNetwork(addr)
        offset <<= (128 - self.ipv6.prefixlen)
        self.ipv6.ip.__iadd__(offset)
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
