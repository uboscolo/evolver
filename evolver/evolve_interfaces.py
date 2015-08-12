import re
from evolve_log import *

logger = GetLogger()


class Interface(object):

    def __init__(self, name, bandwidth):
        self.name = name
        self.bandwidth = bandwidth
        self.mtu = None
        self.networks = [ ]
        self.verify_only = True

    def AddConnectivity(self, node, conn, net):
        logger.error("Method not implemented")
        assert False

    def AddLink(self, node, conn, net, mtu=None):
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

    def AddLink(self, node, conn, net, mtu=None):
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
                    break
            if link_exists:
                cmd_string = "setvr %s vconfig rem %s.%s" % (net.vr, self.name, conn.vlan)
                r = c.Run([cmd_string])
            cmd_string = "setvr %s vconfig add %s %s\n" % (net.vr, self.name, conn.vlan)
            cmd_string += "setvr %s ip link set dev %s.%s up\n" % (net.vr, self.name, conn.vlan)
            if mtu:
                cmd_string += "setvr %s ip link set dev %s.%s mtu %s\n" % (net.vr, self.name, conn.vlan, mtu)
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
            cmd_string = "configure terminal\n"
            cmd_string = "vrf context %s\n" % net.vr
            cmd_string = "exit\n"
            cmd_string = "no interface vlan %s\n" % conn.vlan
            cmd_string = "interface vlan %s\n" % conn.vlan
            cmd_string = "no shutdown\n"
            cmd_string = "vrf member %s\n" % net.vr 
            if net.ipv4:
                cmd_string = "ip address %s/%s\n" % (net.ipv4.ip, net.ipv4.prefixlen)
            if net.ipv6:
                cmd_string = "ipv6 address %s/%s\n" % (net.ipv6.ip, net.ipv6.prefixlen)
            cmd_string = "end\n"
            r = c.Run([cmd_string])

    def AddLink(self, node, conn, net, mtu=None):
        link_exists = self.VerifyLink(node, conn, net)
        if self.verify_only: 
            if not link_exists:
                logger.error("Interface or port-channel do not exist")
                assert False
        else:
            c = node.conn
            if conn.port_channel:
                if not link_exists:
                    logger.debug("Port channel %s not found" % conn.port_channel)
                    cmd_string = "configure terminal\n"
                    cmd_string += "feature lacp\n"
                    cmd_string += "interface port-channel %s\n" % conn.port_channel
                    cmd_string += "switchport mode trunk\n"
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
                            break
                    cmd_string = "end"
                    r = c.Run([cmd_string])
            # configure the interface
            cmd_string = "configure terminal\n"
            cmd_string += "interface ethernet %s\n" % self.name
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
                        break
            logger.debug("Looking if all vlans 1-4094 are allowed ...")
            cmd_string = "show interface ethernet %s switchport | grep \"Trunking VLANs Allowed\"" % self.name
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'Trunking VLANs Allowed: 1-4094', line)
                if res_obj:
                    logger.debug("All vlans 1-4094 are allowed, changing to none")
                    cmd_string = "switchport trunk allowed vlan none"
                    r = c.Run([cmd_string])
                    break
            # Add the vlans
            if conn.port_channel:
                cmd_string = "channel-group %s force mode active\n" % conn.port_channel
                cmd_string += "interface port-channel %s\n" % conn.port_channel
            cmd_string += "switchport trunk allowed vlan add %s\n" % conn.vlan
            cmd_string += "end\n"
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
                cmd_string = "configure terminal\n"
                cmd_string += "vlan %s\n" % conn.vlan
                cmd_string += "exit\n"
                r = c.Run([cmd_string])
                break
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

    def AddLink(self, node, conn, net, mtu=None):
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
                break
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
                break
        # verify
        if not link_exists:
            logger.error("Interface %s not found, or status is DOWN" % self.name)
            assert False
 
    def AddConnectivity(self, node, conn, net):
        # check if network exists, fail otherwise
        c = node.conn


