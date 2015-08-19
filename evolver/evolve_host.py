from evolve_log import *
from evolve_interfaces import *
from evolve_network import *
from connect import *

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

    def AddNetworkInterface(self, dev, net, vlan, mtu):
        logger.error("Method not implemented")
        assert False

    def AddPortChannel(self, pname, intf):
        logger.debug("Stub Method")
        pass

    def AddRoute(self, net_from, net_to, net_via, ver=4):
        logger.error("Method not implemented")
        assert False

    def AddVlan(self, vlan):
        logger.debug("Stub Method")
        pass

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
        new_intf.VerifyLink(self.conn, None)
        new_intf.Bringup(self.conn)
        new_intf.RingSize(self.conn)

    def AddNetworkInterface(self, dev, net, vlan, mtu):
        # Only handle vlan tagged interfaces
        name = "%s.%s" % (dev.name, vlan) 
        if name in self.interfaces_by_name.keys():
            new_intf = self.interfaces_by_name[name]
        else:
            new_intf = LinuxInterface(name, None)
            self.interfaces.append(new_intf)
            self.interfaces_by_name[name] = new_intf
            new_intf.verify_only = self.verify_only
        new_intf.VerifyLink(self.conn, net)
        new_intf.AddLink(self.conn, net, mtu)
        new_intf.AddNetwork(self.conn, net)

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
        self.port_channels = [ ]
        self.port_channels_by_name = { }
        self.vlans = [ ]

    def AddInterface(self, name, bandwidth):
        new_intf = StarOsInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        new_intf.verify_only = self.verify_only
        new_intf.VerifyLink(self.conn, None)

    def AddNetworkInterface(self, dev, net, vlan, mtu):
        # Only handle vlan tagged interfaces
        name = "vlan-%s" % vlan 
        if name in self.interfaces_by_name.keys():
            new_intf = self.interfaces_by_name[name]
        else:
            new_intf = StarOsInterface(name, None)
            self.interfaces.append(new_intf)
            self.interfaces_by_name[name] = new_intf
            new_intf.verify_only = self.verify_only
        new_intf.VerifyLink(self.conn, net)

    def AddLoopback(self, addr, vr, num=1):
        for l in range(num):
            logger.debug("Checking for loopback ...")

    def AddPortChannel(self, pname, intf):
        if not pname:
            logger.debug("No port-channel to be added")
            return
        c = self.conn
        logger.debug("Adding port-channel %s ..." % pname)
        if not pname in self.port_channels_by_name.keys():
            p = PortChannel(pname)
            logger.debug("Looking for port-channel %s ..." % p.name)
            if self.verify_only:
                logger.warning("Port-channel %s not found, proceeding ..." % p.name)
            self.port_channels.append(p)
            self.port_channels_by_name[p.name] = p
        else:
            p = self.port_channels_by_name[pname]
        if not intf.port_channel:
            intf.port_channel = p

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
        self.port_channels = [ ]
        self.port_channels_by_name = { }
        self.vlans = [ ]

    def AddInterface(self, name, bandwidth):
        new_intf = SwitchInterface(name, bandwidth)
        self.interfaces.append(new_intf)
        self.interfaces_by_name[name] = new_intf
        new_intf.verify_only = self.verify_only
        new_intf.VerifyLink(self.conn, None)
        new_intf.Bringup(self.conn)

    def AddNetworkInterface(self, dev, net, vlan, mtu):
        # Only handle vlan tagged interfaces
        name = "Vlan%s" % vlan 
        if name in self.interfaces_by_name.keys():
            new_intf = self.interfaces_by_name[name]
        else:
            new_intf = SwitchInterface(name, None)
            self.interfaces.append(new_intf)
            self.interfaces_by_name[name] = new_intf
            new_intf.verify_only = self.verify_only
        new_intf.VerifyLink(self.conn, net)
        new_intf.AddLink(self.conn, net, mtu)
        new_intf.AddVlan(self.conn, dev, vlan)
        new_intf.AddNetwork(self.conn, net)

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
                c.Run([cmd_string])
                cmd_string = "interface loopback %s" % if_num
                c.Run([cmd_string])
                cmd_string = "vrf member %s" % vr
                c.Run([cmd_string])
                cmd_string = "ip address %s" % ip
                c.Run([cmd_string])
                cmd_string = "end"
                c.Run([cmd_string])

    def AddPortChannel(self, pname, intf):
        if not pname:
            logger.debug("No port-channel to be added")
            return
        c = self.conn
        logger.debug("Adding port-channel %s ..." % pname)
        if not pname in self.port_channels_by_name.keys():
            p = PortChannel(pname)
            logger.debug("Looking for port-channel %s ..." % p.name)
            found = False
            cmd_string = "show port-channel summary"
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'([\d]+).*Po([\d]+)', line)
                if res_obj:
                    po = res_obj.group(1)
                    if po == p.name:
                        logger.debug("Found port channel %s" % po)
                        found = True
                        break
            if not found: 
                if self.verify_only:
                    logger.error("Did not find port-channel %s, can't proceed" % p.name)
                    assert False
                cmd_string = "configure terminal"
                c.Run([cmd_string])
                cmd_string = "feature lacp"
                c.Run([cmd_string])
                cmd_string = "interface port-channel %s" % p.name
                c.Run([cmd_string])
                cmd_string = "switchport mode trunk"
                c.Run([cmd_string])
                logger.debug("Looking if all vlans 1-4094 are allowed, in case disable ...")
                cmd_string = "show interface port-channel %s switchport | grep \"Trunking VLANs Allowed\"" % p.name
                r = c.Run([cmd_string])
                for line in r.splitlines():
                    res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
                    if res_obj:
                        logger.debug("All vlans 1-4094 are allowed, changing to none")
                        cmd_string = "switchport trunk allowed vlan none"
                        r = c.Run([cmd_string])
                        break
                cmd_string = "end"
                r = c.Run([cmd_string])
            self.port_channels.append(p)
            self.port_channels_by_name[p.name] = p
        else:
            p = self.port_channels_by_name[pname]
        if not intf.port_channel:
            logger.debug("Adding port-channel %s to interface %s" % (p.name, intf.name))
            intf.port_channel = p
            cmd_string = "configure terminal"
            c.Run([cmd_string])
            cmd_string = "interface %s" % intf.name
            c.Run([cmd_string])
            cmd_string = "channel-group %s force mode active" % p.name
            c.Run([cmd_string])
            cmd_string = "end"
            c.Run([cmd_string])

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

    def AddVlan(self, vlan):
        logger.debug("Adding vlan %s ..." % vlan)
        if vlan in self.vlans:
            logger.debug("Vlan %s already added" % vlan)
            return
        if self.verify_only:
            logger.error("Did not find vlan %s, can't proceed" % vlan)
            assert False
        self.vlans.append(vlan)
        c = self.conn
        cmd_string = "show vlan id %s" % vlan
        r = c.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'VLAN ([\d]+) not found in current VLAN database', line)
            if res_obj:
                logger.debug("Vlan %s not found, adding ..." % vlan)
                cmd_string = "configure terminal"
                c.Run([cmd_string])
                cmd_string = "vlan %s" % vlan
                c.Run([cmd_string])
                cmd_string = "exit"
                c.Run([cmd_string])
                break
        logger.debug("Added vlan %s" % vlan)

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
            cmd_string = "ping %s count 2 timeout 2 vrf %s source %s" % (remote_net.ipv4.ip, local_net.vr, local_net.ipv4.ip)
        elif ver == 6:
            if not remote_net.ipv6 or remote_net.ipv6.ip == remote_net.ipv6.network:
                logger.debug("No ipv4 network")
                return False
            cmd_string = "ping6 %s count 2 timeout 2 vrf %s" % (remote_net.ipv6.ip, local_net.vr)
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


class Make(object):
 
    def __init__(self, name):
        self.name = name
        self.model = None
        self.type = None


