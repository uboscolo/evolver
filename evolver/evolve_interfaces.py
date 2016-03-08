import re
from evolve_log import*

logger = GetLogger()


class Interface(object):

    def __init__(self, name, bandwidth):
        self.name = name
        self.bandwidth = bandwidth
        self.mtu = None
        self.vlan = None
        self.port_channel = None
        self.status = False
        self.networks = [ ]
        self.vlans = [ ]
        self.verify_only = True

    def AddLink(self, c, net, mtu=None):
        logger.error("Method not implemented")
        assert False

    def AddNetwork(self, c, net):
        logger.error("Method not implemented")
        assert False

    def VerifyLink(self, c, net=None):
        logger.error("Method not implemented")
        assert False


class LinuxInterface(Interface):

    def __init__(self, name, bandwidth):
        super(LinuxInterface, self).__init__(name, bandwidth)

    def AddNetwork(self, c, net):
        logger.debug("Adding Network ...")
        self.networks.append(net)
        if net.ipv4 and not self.verify_only:
            cmd_string = "setvr %s ip addr add %s dev %s" % (net.vr, net.ipv4, self.name)
            r = c.Run([cmd_string])
        if net.ipv6 and not self.verify_only:
            cmd_string = "setvr %s ip -6 addr add %s dev %s" % (net.vr, net.ipv6, self.name)
            r = c.Run([cmd_string])

    def AddLink(self, c, net, mtu=None):
        logger.debug("Adding link %s ..." % self.name)
        if self.verify_only: 
            if not self.status:
                logger.error("Link does not exist or is not up, can't proceed")
                assert False
        else:
            if not self.status:
                # Find if device exists, might be just down
                cmd_string = "setvr %s ip link show dev %s" % (net.vr, self.name)
                r = c.Run([cmd_string])
                for line in r.splitlines():
                    res_obj = re.search(r'Device (.*) does not exist.', line)
                    if res_obj:
                        logger.warning("Device %s does not exist, creating ..." % self.name)
                        cmd_string = "modprobe 8021q"
                        c.Run([cmd_string])
                        break
            else:
                cmd_string = "setvr %s vconfig rem %s" % (net.vr, self.name)
                c.Run([cmd_string])
            dev = self.name.split('.')[0] 
            vlan = self.name.split('.')[1] 
            cmd_string = "setvr %s vconfig add %s %s" % (net.vr, dev, vlan)
            c.Run([cmd_string])
            cmd_string = "setvr %s ip link set dev %s up" % (net.vr, self.name)
            c.Run([cmd_string])
            if mtu:
                cmd_string = "setvr %s ip link set dev %s mtu %s" % (net.vr, self.name, mtu)
                c.Run([cmd_string])
            self.status = True

    def Bringup(self, c):
        # Device might not be there, check
        if not self.status:
            cmd_string = "ip link show dev %s" % self.name
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'Device (.*) does not exist.', line)
                if res_obj:
                    logger.error("Device %s doesn't exist" % self.name)
                    assert False
            # Device exists
            cmd_string = "ip link set dev %s up" % self.name
            r = c.Run([cmd_string])
            self.status = True
        # Check for link characteristics
        cmd_string = "ip link show dev %s" % self.name
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
                    if not self.verify_only:
                        cmd_string = "ip link set dev %s qlen 10000" % self.name
                        r = c.Run([cmd_string])
                return
        logger.error("Device %s is not up, can't proceed" % self.name)
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

    def VerifyLink(self, c, net=None):
        if not self.status:
            logger.debug("Verifying if link %s is up" % self.name)
            if net:
                cmd_string = "setvr %s ip link show dev %s up" % (net.vr, self.name)
            else:
                cmd_string = "ip link show dev %s up" % self.name
            r = c.Run([cmd_string])
            for line in r.splitlines():
                res_obj = re.search(r'[\d]+: ([\w\d.@]+): <.*> mtu ([\d]+)', line)
                if res_obj:
                    device = res_obj.group(1)
                    mtu = res_obj.group(2)
                    if self.name in device:
                        logger.debug("Device %s found and up (mtu: %s)" % (self.name, mtu))
                        self.status = True
                        break

class SwitchInterface(Interface):

    def __init__(self, name, bandwidth):
        super(SwitchInterface, self).__init__(name, bandwidth)

    def AddNetwork(self, c, net):
        if not net.ipv4 and not net.ipv6:
            logger.debug("No IP network to be added")
            return 
        self.networks.append(net)
        if not self.verify_only:
            cmd_string = "configure terminal"
            c.Run([cmd_string])
            cmd_string = "interface %s" % self.name
            c.Run([cmd_string])
            if net.ipv4:
                cmd_string = "ip address %s/%s" % (net.ipv4.ip, net.ipv4.prefixlen)
                c.Run([cmd_string])
            if net.ipv6:
                cmd_string = "ipv6 address %s/%s" % (net.ipv6.ip, net.ipv6.prefixlen)
                c.Run([cmd_string])
            cmd_string = "end"
            c.Run([cmd_string])

    def AddLink(self, c, net, mtu=None):
        logger.debug("Adding link %s ..." % self.name)
        if self.verify_only: 
            if not self.status:
                logger.error("Link does not exist or is not up, can't proceed")
                assert False
        else:
            if not self.status:
                cmd_string = "configure terminal"
                c.Run([cmd_string])
                cmd_string = "vrf context %s" % net.vr
                c.Run([cmd_string])
                cmd_string = "exit"
                c.Run([cmd_string])
                cmd_string = "no interface %s" % self.name
                c.Run([cmd_string])
                cmd_string = "interface %s" % self.name
                c.Run([cmd_string])
                cmd_string = "no shutdown"
                c.Run([cmd_string])
                cmd_string = "vrf member %s" % net.vr 
                c.Run([cmd_string])
                cmd_string = "end"
                c.Run([cmd_string])

    def AddVlan(self, c, dev, vlan):
        if not self.verify_only: 
            logger.debug("Adding vlan %s to device %s ..." % (vlan, dev.name))
            if dev.port_channel:
                if not vlan in dev.port_channel.vlans:
                    dev.port_channel.vlans.append(vlan)
                    cmd_string = "configure terminal"
                    c.Run([cmd_string])
                    cmd_string = "interface port-channel %s" % dev.port_channel.name
                    c.Run([cmd_string])
                    cmd_string = "switchport trunk allowed vlan add %s" % vlan
                    c.Run([cmd_string])
                    cmd_string = "end"
                    c.Run([cmd_string])
            else:
                if not vlan in dev.vlans:
                    dev.vlans.append(vlan)
                    cmd_string = "configure terminal"
                    c.Run([cmd_string])
                    cmd_string = "interface %s" % dev.name
                    c.Run([cmd_string])
                    cmd_string = "switchport trunk allowed vlan add %s" % vlan
                    c.Run([cmd_string])
                    cmd_string = "end"
                    c.Run([cmd_string])

    def Bringup(self, c):
        if not self.status:
            logger.debug("Interface doesn't exist, can' proceed")
            assert False
        # configure the interface
        if not self.verify_only:
            cmd_string = "configure terminal"
            c.Run([cmd_string])
            cmd_string = "interface %s" % self.name
            c.Run([cmd_string])
            logger.debug("Looking if mode is trunk ...")
            cmd_string = "show interface %s switchport | grep \"Operational Mode\"" % self.name
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
            cmd_string = "show interface %s switchport | grep \"Trunking VLANs Allowed\"" % self.name
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

    def VerifyLink(self, c, net):
        # it could also verify if vrf is correct
        if not self.status:
            logger.debug("Looking for interface %s ..." % self.name)
            cmd_string = "show interface %s brief" % self.name
            try:
                r = c.Run([cmd_string])
            except Exception as e:
                logger.debug("Interface not yet created: {0}".format(e))
                return
            for line in r.splitlines():
                res_obj = re.search(r'^([a-zA-Z]+)([\d/]+) ', line)
                if res_obj:
                    intf1 = res_obj.group(1)
                    intf2 = res_obj.group(2)
                    if intf2 in self.name:
                        logger.debug("Found interface %s %s" % (intf1, intf2))
                        self.status = True
                        break


class StarOsInterface(Interface):

    def __init__(self, name, bandwidth):
        super(StarOsInterface, self).__init__(name, bandwidth)

    def VerifyLink(self, c, net):
        logger.debug("Checking if link exists %s" % self.name)
        if not net:
            logger.debug("Insert here a check for the port")
            return
        # revisit
        # This second part should be checked somewhere else
        #if self.port_channel and not (net.ipv4 or net.ipv6):
        #    logger.debug("Secondary member of a port channel")
        #    return
        #link_exists =  False       
        #cmd_string = "context %s" % (net.vr)
        #r = c.Run([cmd_string])
        #cmd_string = "show ip interface | grep \"Bound to %s\"" % self.name
        #r = c.Run([cmd_string])
        #for line in r.splitlines():
        #    res_obj = re.search(r'IP State:.*UP', line)
        #    if res_obj:
        #        logger.debug("Interface %s found, status is UP" % self.name)
        #        link_exists =  True
        #        break
        ##if node.make.model == "ASR5500":
        ## Assuming 5500
        #card, port = self.name.split("/")
        #if card == "5":
        #    new_intf = "6/" + port
        #elif card == "6":
        #    new_intf = "5/" + port
        #else:
        #    logger.error("Unexpected interface" % self.name)
        #    assert False
        #cmd_string = "show ip interface | grep \"Bound to %s\"" % new_intf
        #r = c.Run([cmd_string])
        #for line in r.splitlines():
        #    res_obj = re.search(r'IP State:.*UP', line)
        #    if res_obj:
        #        logger.debug("Interface %s found, status is UP" % new_intf)
        #        link_exists =  True
        #        break
        ## verify
        #if not link_exists:
        #    logger.error("Interface %s not found, or status is DOWN" % self.name)
        #    assert False

class PortChannel(object):

    def __init__(self, name):
        self.name = name
        self.vlans = [ ]

