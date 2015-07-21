import xml.etree.ElementTree as ET
import math
import netaddr
from evolve_log import *
from lattice import *

logger = GetLogger()

class CallGeneratorHandler(object):

    def __init__(self, type):
        # type: lattice_clp
        self.type = type
        self.cli = None
        self.clp = None
        self.affinity = None
        self.user_config = None


class Master(object):

    def __init__(self, name):
        self.name = name
        self.clients = [ ]
        self.servers = [ ]
        self.traffic_models = [ ]
        self.traffic_models_by_name = { }
        self.callgenerators = [ ]
        self.lte_networks = [ ]
        self.lte_networks_by_name = { }

    def CreateServers(self):
        for s in self.servers:
            tm = self.traffic_models_by_name[s.tm_handler]
            gen = "%sServer" % tm.protocol
            out = "create_server {%s handle %s affinity %s vr %s stargen_generator %s rsa %s rv6sa %s dst_port %s xml_file %s}" % (s.host, s.handle, s.affinity, s.vr, gen, s.dst_ipv4_addr, s.dst_ipv6_addr, tm.dst_port, tm.descriptor)
            logger.debug(out)

    def CreateClients(self):
        for c in self.clients:
            tm = self.traffic_models_by_name[c.tm_handler]
            gen = "%sGen" % tm.protocol
            out = "create_client {%s handle %s affinity %s vr %s callgen_type %s clp %s cli %s af %s user_config %s stargen_generator %s rsa %s rv6sa %s dst_port %s xml_file %s}" % (c.host, c.handle, c.affinity, c.vr, c.cg_handler.type, c.cg_handler.clp, c.cg_handler.cli, c.cg_handler.affinity, c.cg_handler.user_config, gen, c.dst_ipv4_addr, c.dst_ipv6_addr, tm.dst_port, tm.descriptor)
            logger.debug(out)

    def CreateLatticeConfigs(self):
        for l in self.callgenerators:
            lt = self.lte_networks_by_name[l.lte_network]
            logger.debug("configure")
            logger.debug("    lte-policy")
            logger.debug("        tai-mgmt-db tai-db-1")
            logger.debug("            tai-mgmt-obj tai-obj-1")
            logger.debug("                tai mcc %s mnc %s tac %s" % (lt.mcc, lt.mnc, lt.tac))
            logger.debug("                sgw ipv4-address %s" % l.control_plane.local_ipv4_addr.ip)
            logger.debug("            #exit")
            logger.debug("        #exit")
            logger.debug("    #exit")
            logger.debug("    network-topology")
            logger.debug("        ue-set name ue-set1")
            for a in lt.apns:
                logger.debug("            pdn apn %s type %s" % (a.name, a.type))
                logger.debug("                location-reporting tai")
                logger.debug("                location-reporting cgid")
                logger.debug("            count %s" % l.call_model.count)
                logger.debug("            initial-imsi %s%s%s00001" % (lt.mcc, lt.mnc, l.imsi_fill))
                logger.debug("            initial-imei 999991546123451")
                logger.debug("            kasme 34595956959")
                logger.debug("        #exit")
            logger.debug("        hss-service name hss-1")
            for a in lt.apns:
                logger.debug("            pdn apn %s type %s" % (a.name, a.type))
                logger.debug("                qci %s" % (a.qci))
                logger.debug("                arp %s" % (a.arp))
                logger.debug("                pre-emption-capability %s" % (a.pec))
                logger.debug("            #exit")
                logger.debug("        #exit")
            logger.debug("        enodeb-set name enb-1")
            logger.debug("            global-type macro")
            logger.debug("            count 1")
            logger.debug("            initial-id %s000 mcc %s mnc %s" % (l.imsi_fill, lt.mcc, lt.mnc))
            logger.debug("            supported-tai mcc %s mnc %s initial-tac %s count 1 shared-count 1" % (lt.mcc, lt.mnc, lt.tac))
            logger.debug("            supported-cgid mcc %s mnc %s initial-cgid 1 count 1 shared-count 0" % (lt.mcc, lt.mnc))
            logger.debug("        #exit")
            logger.debug("        mme-set name mme-1")
            logger.debug("            count 1")
            logger.debug("            associate tai-mgmt-db tai-db-1")
            logger.debug("            policy tau set-ue-time enable")
            logger.debug("            policy network dual-addressing-supported")
            logger.debug("            enodeb-set enb-1")
            logger.debug("            hss-service hss-1")
            logger.debug("        #exit")
            logger.debug("        sgw-set name sgw-1")
            logger.debug("            count 1")
            logger.debug("            plmn mcc %s mnc %s" % (lt.mcc, lt.mnc))
            logger.debug("            s5")
            logger.debug("                source ipv4-network %s port 2123" % l.control_plane.local_ipv4_addr)
            logger.debug("                destination ipv4-address %s port 2123" % l.control_plane.remote_ipv4_addr.ip)
            logger.debug("            #exit")
            logger.debug("            s5u")
            logger.debug("                source ipv4-network %s port 2152" % l.data_plane.local_ipv4_addr)
            logger.debug("            #exit")
            logger.debug("            bind")
            logger.debug("        #exit")
            logger.debug("        hsgw-set name hsgw-1")
            logger.debug("            count 1")
            logger.debug("            initial-id 1")
            logger.debug("            plmn mcc %s mnc %s" % (lt.mcc, lt.mnc))
            logger.debug("            nai-realm nai.epc.mnc0%s.mcc%s.3gppnetwork.org" % (lt.mnc, lt.mcc))
            logger.debug("            s2a")
            logger.debug("                source ipv6-network %s" % l.control_plane.local_ipv6_addr)
            logger.debug("                destination ipv6-address %s" % l.control_plane.remote_ipv6_addr.ip)
            logger.debug("            #exit")
            logger.debug("            s2au")
            logger.debug("                source ipv6-network %s" % l.data_plane.local_ipv6_addr)
            logger.debug("            #exit")
            logger.debug("            bind")
            logger.debug("        #exit")
            logger.debug("    #exit")
            logger.debug("    traffic-model name tm-1")
            logger.debug("        tun-interface name %s" % l.tunnel_dev)
            logger.debug("        local ip address 1.1.1.1")
            logger.debug("        local ipv6 address 1111::1.1.1.1")
            logger.debug("        remote ip network %s" % l.data_plane.remote_ipv4_addr)
            logger.debug("        remote ipv6 network %s" % l.data_plane.remote_ipv6_addr)
            logger.debug("        #exit")
            logger.debug("    #exit")
            opts = { }
            opts["initial_delay"] = l.call_model.initial_delay
            opts["delay"] = l.call_model.delay
            l.call_model.CallEventSequence(lt.apns, **opts)
            logger.debug("    call-model name %s" % l.call_model.name)
            logger.debug("        ue-set ue-set1")
            logger.debug("        call-event-sequence %s" % l.call_model.name)
            logger.debug("        call-make rate %s" % l.call_model.make_rate)
            logger.debug("        call-break rate %s" % l.call_model.break_rate)
            logger.debug("        traffic-model tm-1")
            logger.debug("    #exit")
            logger.debug("end")



class Stargen(object):

    def __init__(self, handle):
        self.handle = handle
        self.id = None
        self.host = None
        self.affinity = None
        self.vr = None
        self.num_instances = None
        self.cg_handler = None
        self.dst_ipv4_addr = None
        self.dst_ipv6_addr = None
        self.tm_handler = None


class TrafficModel(object):

    def __init__(self, name):
        self.name = name
        # type: HTTP, UDP, ...
        self.protocol = None
        self.dst_port = None
        self.src_port = None
        # XML file
        self.descriptor = None


class ToolParser(object):

    def __init__(self, xml_file):
        self.xml_file = xml_file

    def __AddLattices(self, tag, master):
        assert 'id' in tag.attrib.keys()
        assert 'host' in tag.attrib.keys()
        id = tag.attrib['id']
        host = tag.attrib['host']
        for next_tag in tag:
            if next_tag.tag == "settings":
                assert 'vr' in next_tag.attrib.keys()
                assert 'affinity_offset' in next_tag.attrib.keys()
                assert 'instances' in next_tag.attrib.keys()
                assert 'lte_network' in next_tag.attrib.keys()
                vr = next_tag.attrib['vr']
                aff = next_tag.attrib['affinity_offset']
                num_inst = next_tag.attrib['instances']
                lte_net = next_tag.attrib['lte_network']
            elif next_tag.tag == "control_plane":
                assert 'local_ipv4_addr' in next_tag.attrib.keys()
                assert 'local_ipv6_addr' in next_tag.attrib.keys()
                assert 'remote_ipv4_addr' in next_tag.attrib.keys()
                assert 'remote_ipv6_addr' in next_tag.attrib.keys()
                cl_ipv4 = next_tag.attrib['local_ipv4_addr']
                cl_ipv6 = next_tag.attrib['local_ipv6_addr']
                cr_ipv4 = next_tag.attrib['remote_ipv4_addr']
                cr_ipv6 = next_tag.attrib['remote_ipv6_addr']
            elif next_tag.tag == "data_plane":
                assert 'local_ipv4_addr' in next_tag.attrib.keys()
                assert 'local_ipv6_addr' in next_tag.attrib.keys()
                assert 'remote_ipv4_addr' in next_tag.attrib.keys()
                assert 'remote_ipv6_addr' in next_tag.attrib.keys()
                dl_ipv4 = next_tag.attrib['local_ipv4_addr']
                dl_ipv6 = next_tag.attrib['local_ipv6_addr']
                dr_ipv4 = next_tag.attrib['remote_ipv4_addr']
                dr_ipv6 = next_tag.attrib['remote_ipv6_addr']
            elif next_tag.tag == "call_model":
                assert 'name' in next_tag.attrib.keys()
                assert 'count' in next_tag.attrib.keys()
                assert 'make_rate' in next_tag.attrib.keys()
                assert 'break_rate' in next_tag.attrib.keys()
                assert 'initial_delay' in next_tag.attrib.keys()
                assert 'delay' in next_tag.attrib.keys()
                cname = next_tag.attrib['name']
                count = next_tag.attrib['count']
                mr = next_tag.attrib['make_rate']
                br = next_tag.attrib['break_rate']
                init_delay = next_tag.attrib['initial_delay']
                delay = next_tag.attrib['delay']
            else:
                logger.error("Unexpected tag %s" % next_tag.tag)
                raise
        for i in range(int(num_inst)):
            lattice = Lattice()
            lattice.id = id
            lattice.tunnel_dev = "tun-%s" % i
            lattice.imsi_fill =  "%03d%s" % (int(id), i)
            lattice.lte_network = lte_net 
            lattice.control_plane.local_ipv4_addr = netaddr.IPNetwork(cl_ipv4)
            lattice.control_plane.local_ipv4_addr.__iadd__(i)
            lattice.control_plane.local_ipv6_addr = netaddr.IPNetwork(cl_ipv6)
            lattice.control_plane.local_ipv6_addr.__iadd__(i)
            lattice.control_plane.remote_ipv4_addr = netaddr.IPNetwork(cr_ipv4)
            lattice.control_plane.remote_ipv4_addr.__iadd__(i)
            lattice.control_plane.remote_ipv6_addr = netaddr.IPNetwork(cr_ipv6)
            lattice.control_plane.remote_ipv6_addr.__iadd__(i)
            lattice.data_plane.local_ipv4_addr = netaddr.IPNetwork(dl_ipv4)
            lattice.data_plane.local_ipv4_addr.__iadd__(i)
            lattice.data_plane.local_ipv6_addr = netaddr.IPNetwork(dl_ipv6)
            lattice.data_plane.local_ipv6_addr.__iadd__(i)
            lattice.data_plane.remote_ipv4_addr = netaddr.IPNetwork(dr_ipv4)
            lattice.data_plane.remote_ipv4_addr.__iadd__(i)
            lattice.data_plane.remote_ipv6_addr = netaddr.IPNetwork(dr_ipv6)
            lattice.data_plane.remote_ipv6_addr.__iadd__(i)
            cm = CallModel(cname)
            cm.count = count
            cm.make_rate = mr
            cm.break_rate = br
            cm.initial_delay = init_delay
            cm.delay = delay
            lattice.call_model = cm
            master.callgenerators.append(lattice)
            

    def __AddLteNetwork(self, tag, master):
        assert 'name' in tag.attrib.keys()
        name = tag.attrib['name']
        lte_net = LteNetwork(name)
        for next_tag in tag:
            if next_tag.tag == "parameters":
                assert 'mcc' in next_tag.attrib.keys()
                assert 'mnc' in next_tag.attrib.keys()
                assert 'tac' in next_tag.attrib.keys()
                mcc = next_tag.attrib['mcc']
                mnc = next_tag.attrib['mnc']
                tac = next_tag.attrib['tac']
                lte_net.mcc = mcc
                lte_net.mnc = mnc
                lte_net.tac = tac
            elif next_tag.tag == "apn":
                assert 'name' in next_tag.attrib.keys()
                assert 'type' in next_tag.attrib.keys()
                assert 'qci' in next_tag.attrib.keys()
                assert 'arp' in next_tag.attrib.keys()
                assert 'pec' in next_tag.attrib.keys()
                apn_name = next_tag.attrib['name']
                type = next_tag.attrib['type']
                qci = next_tag.attrib['qci']
                arp = next_tag.attrib['arp']
                pec = next_tag.attrib['pec']
                new_apn = Apn(apn_name)
                new_apn.type = type
                new_apn.qci = qci
                new_apn.arp = arp
                new_apn.pec = pec
                lte_net.apns.append(new_apn)
            else:
                logger.error("Unexpected tag %s" % next_tag.tag)
                raise
        master.lte_networks.append(lte_net)
        master.lte_networks_by_name[name] = lte_net

    def __AddStargens(self, tag, master):
        assert 'id' in tag.attrib.keys()
        assert 'host' in tag.attrib.keys()
        assert 'type' in tag.attrib.keys()
        id = tag.attrib['id']
        host = tag.attrib['host']
        type = tag.attrib['type']
        for next_tag in tag:
            assert next_tag.tag == "settings"
            assert 'vr' in next_tag.attrib.keys()
            assert 'affinity_offset' in next_tag.attrib.keys()
            assert 'instances' in next_tag.attrib.keys()
            assert 'traffic_model' in next_tag.attrib.keys()
            assert 'ipv4_addr' in next_tag.attrib.keys()
            assert 'ipv6_addr' in next_tag.attrib.keys()
            vr = next_tag.attrib['vr']
            aff = next_tag.attrib['affinity_offset']
            num_inst = next_tag.attrib['instances']
            tm = next_tag.attrib['traffic_model']
            ipv4 = next_tag.attrib['ipv4_addr']
            ipv6 = next_tag.attrib['ipv6_addr']
        for i in range(int(num_inst)):
            handle = "%s-%s-%s" % (type, id, i)
            stargen = Stargen(handle)
            stargen.id = id
            stargen.host = host
            stargen.affinity = int(math.pow(2, (int(aff) + i)))
            stargen.vr = vr
            stargen.num_instances = num_inst
            stargen.dst_ipv4_addr = netaddr.IPAddress(ipv4)
            stargen.dst_ipv4_addr.__iadd__(i)
            stargen.dst_ipv6_addr = netaddr.IPAddress(ipv6)
            stargen.dst_ipv6_addr.__iadd__(i)
            stargen.tm_handler = tm
            if type == "client":
                cgh = CallGeneratorHandler("lattice_clp")
                cgh.cli = "127.0.0.1"
                cgh.clp = 65500 - (i * 3)
                cgh.affinity = int(aff) + i
                cgh.user_config = "/localdisk/master_files/lattice%s_%s.cfg" % (id, i)
                stargen.cg_handler = cgh
                master.clients.append(stargen)
            elif type == "server":
                master.servers.append(stargen)
            else:
                logger.error("Unexpected stargen type %s" % type)
                raise

    def __AddTrafficMix(self, tag, master):
        assert 'name' in tag.attrib.keys()
        name = tag.attrib['name']
        for next_tag in tag:
            assert next_tag.tag == "map"
            assert 'protocol' in next_tag.attrib.keys()
            assert 'port' in next_tag.attrib.keys()
            assert 'descriptor' in next_tag.attrib.keys()
            prot = next_tag.attrib['protocol']
            port = next_tag.attrib['port']
            desc = next_tag.attrib['descriptor']
        tm = TrafficModel(name)
        tm.protocol = prot
        tm.dst_port = port
        tm.descriptor = desc
        master.traffic_models.append(tm)
        master.traffic_models_by_name[name] =  tm

    def ParseXml(self):
        tree = ET.parse(self.xml_file)
        root_tag = tree.getroot()
        assert root_tag.tag == "tools"
        assert 'name' in root_tag.attrib.keys()
        name = root_tag.attrib['name']
        master = Master("Suite3")
        for next_tag in root_tag:
            if next_tag.tag == "stargen":
                self.__AddStargens(next_tag, master)
            elif next_tag.tag == "traffic_mix":
                self.__AddTrafficMix(next_tag, master)
            elif next_tag.tag == "lattice":
                self.__AddLattices(next_tag, master)
            elif next_tag.tag == "lte_network":
                self.__AddLteNetwork(next_tag, master)
            else:
                logger.error("Unknown tag %s" % next_tag.tag)
                raise
        return master
