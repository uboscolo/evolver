import xml.etree.ElementTree as ET
import math
import netaddr
from evolve_log import *
from connect import *
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
        self.call_model = None


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
        self.masterfile = None
        self.initfile = None
        self.support_lps_dir = None
        self.conn = None
        self.screen = Screen(name)

    def CreateServers(self):
        cmd_string = "echo -e \""
        cmd_string += "\n#Servers"
        cmd_string += "\" >> %s\n" % self.masterfile
        self.conn.Run([cmd_string])
        for s in self.servers:
            tm = self.traffic_models_by_name[s.tm_handler]
            gen = "%sServer" % tm.protocol
            out = "create_server {%s handle %s affinity %s vr %s stargen_generator %s rsa %s rv6sa %s dst_port %s xml_file %s}" % (s.host, s.handle, s.affinity, s.vr, gen, s.dst_ipv4_addr, s.dst_ipv6_addr, tm.dst_port, tm.descriptor)
            logger.debug(out)
            cmd_string = "echo -e \""
            cmd_string += "%s" % out
            cmd_string += "\" >> %s\n" % self.masterfile
            self.conn.Run([cmd_string])

    def CreateClients(self):
        cmd_string = "echo -e \""
        cmd_string += "\n#Clients"
        cmd_string += "\" >> %s\n" % self.masterfile
        self.conn.Run([cmd_string])
        for c in self.clients:
            # get callgenerator object via id
            c_ref = None
            for o in self.callgenerators:
                if o.id == c.id:
                    logger.debug("Found associated object id %s" % o.id)
                    c_ref = o
                    break
            if not c_ref:
                logger.error("Did not find associated object, can't proceed")
                assert False
            tm = self.traffic_models_by_name[c.tm_handler]
            gen = "%sGen" % tm.protocol
            out = "create_client {%s handle %s affinity %s vr %s callgen_type %s clp %s cli %s af %s user_config %s call_model %s stargen_generator %s rsa %s rv6sa %s dst_port %s txrate 1 %s xml_file %s}" % (c.host, c.handle, c.affinity, c.vr, c.cg_handler.type, c.cg_handler.clp, c.cg_handler.cli, c.cg_handler.affinity, c.cg_handler.user_config, c_ref.call_model.name, gen, c.dst_ipv4_addr, c.dst_ipv6_addr, tm.dst_port, tm.data_version, tm.descriptor)
            logger.debug(out)
            cmd_string = "echo -e \""
            cmd_string += "%s" % out
            cmd_string += "\" >> %s\n" % self.masterfile
            self.conn.Run([cmd_string])
        # Common Settings
        cmd_string = "echo -e \""
        cmd_string += "\n#Common Settings\n"
        cmd_string += "dynamic_address \\\"yes\\\"\n"
        cmd_string += "idle_timeout 2000\n"
        cmd_string += "\" >> %s" % self.masterfile
        self.conn.Run([cmd_string])
        cmd_string = "echo -e \""
        cmd_string += "start_all %s" % self.masterfile
        cmd_string += "\" >> %s" % self.initfile
        self.conn.Run([cmd_string])

    def CreateLatticeConfigs(self):
        for l in self.callgenerators:
            # get client object via id
            c_ref = None
            for o in self.clients:
                logger.debug("client ID: %s, calgen ID: %s" % (o.id, l.id))
                if o.id == l.id:
                    c_ref = o
                    break
            if not c_ref:
                logger.error("Did not find associated object, can't proceed")
                assert False
            lt = self.lte_networks_by_name[l.lte_network]
            # remove, verify file is not there ...
            cmd_string = "rm %s" % c_ref.cg_handler.user_config
            self.conn.Run([cmd_string])
            cmd_list = [ ]
            cmd_list.append("configure")
            cmd_list.append("    lte-policy")
            cmd_list.append("        tai-mgmt-db tai-db-1")
            cmd_list.append("            tai-mgmt-obj tai-obj-1")
            cmd_list.append("                tai mcc %s mnc %s tac %s" % (lt.mcc, lt.mnc, lt.tac))
            cmd_list.append("                sgw ipv4-address %s" % l.control_plane.local_ipv4_addr.ip)
            cmd_list.append("            #exit")
            cmd_list.append("        #exit")
            cmd_list.append("    #exit")
            cmd_list.append("    network-topology")
            cmd_list.append("        ue-set name ue-set1")
            for a in lt.apns:
                cmd_list.append("            pdn apn %s type %s" % (a.name, a.type))
                cmd_list.append("                location-reporting tai")
                cmd_list.append("                location-reporting cgid")
                cmd_list.append("        #exit")
            cmd_list.append("            count %s" % l.call_model.count)
            cmd_list.append("            initial-imsi %s%s%s00001" % (lt.mcc, lt.mnc, l.imsi_fill))
            cmd_list.append("            initial-imei 999991546123451")
            cmd_list.append("            kasme 34595956959")
            cmd_list.append("        #exit")
            cmd_list.append("        hss-service name hss-1")
            for a in lt.apns:
                cmd_list.append("            pdn apn %s type %s" % (a.name, a.type))
                cmd_list.append("                qci %s" % (a.qci))
                cmd_list.append("                arp %s" % (a.arp))
                cmd_list.append("                pre-emption-capability %s" % (a.pec))
                cmd_list.append("            #exit")
            cmd_list.append("        #exit")
            cmd_list.append("        enodeb-set name enb-1")
            cmd_list.append("            global-type macro")
            cmd_list.append("            count 1")
            cmd_list.append("            initial-id %s000 mcc %s mnc %s" % (l.imsi_fill, lt.mcc, lt.mnc))
            cmd_list.append("            supported-tai mcc %s mnc %s initial-tac %s count 1 shared-count 1" % (lt.mcc, lt.mnc, lt.tac))
            cmd_list.append("            supported-cgid mcc %s mnc %s initial-cgid 1 count 1 shared-count 0" % (lt.mcc, lt.mnc))
            cmd_list.append("        #exit")
            cmd_list.append("        mme-set name mme-1")
            cmd_list.append("            count 1")
            cmd_list.append("            associate tai-mgmt-db tai-db-1")
            cmd_list.append("            policy tau set-ue-time enable")
            cmd_list.append("            policy network dual-addressing-supported")
            cmd_list.append("            enodeb-set enb-1")
            cmd_list.append("            hss-service hss-1")
            cmd_list.append("        #exit")
            cmd_list.append("        sgw-set name sgw-1")
            cmd_list.append("            count 1")
            cmd_list.append("            plmn mcc %s mnc %s" % (lt.mcc, lt.mnc))
            cmd_list.append("            s5")
            cmd_list.append("                source ipv4-network %s port 2123" % l.control_plane.local_ipv4_addr)
            cmd_list.append("                destination ipv4-address %s port 2123" % l.control_plane.remote_ipv4_addr.ip)
            cmd_list.append("            #exit")
            cmd_list.append("            s5u")
            cmd_list.append("                source ipv4-network %s port 2152" % l.data_plane.local_ipv4_addr)
            cmd_list.append("            #exit")
            cmd_list.append("            bind")
            cmd_list.append("        #exit")
            cmd_list.append("        hsgw-set name hsgw-1")
            cmd_list.append("            count 1")
            cmd_list.append("            initial-id 1")
            cmd_list.append("            plmn mcc %s mnc %s" % (lt.mcc, lt.mnc))
            cmd_list.append("            nai-realm nai.epc.mnc0%s.mcc%s.3gppnetwork.org" % (lt.mnc, lt.mcc))
            cmd_list.append("            s2a")
            cmd_list.append("                source ipv6-network %s" % l.control_plane.local_ipv6_addr)
            cmd_list.append("                destination ipv6-address %s" % l.control_plane.remote_ipv6_addr.ip)
            cmd_list.append("            #exit")
            cmd_list.append("            s2au")
            cmd_list.append("                source ipv6-network %s" % l.data_plane.local_ipv6_addr)
            cmd_list.append("            #exit")
            cmd_list.append("            bind")
            cmd_list.append("        #exit")
            cmd_list.append("    #exit")
            cmd_list.append("    traffic-model name tm-1")
            cmd_list.append("        tun-interface name %s" % l.tunnel_dev)
            cmd_list.append("        local ip address 1.1.1.1")
            cmd_list.append("        local ipv6 address 1111::1.1.1.1")
            cmd_list.append("        remote ip network %s/32" % c_ref.dst_ipv4_addr)
            cmd_list.append("        remote ipv6 network %s/128" % c_ref.dst_ipv6_addr)
            cmd_list.append("        #exit")
            cmd_list.append("    #exit")
            opts = { }
            opts["initial_delay"] = l.call_model.initial_delay
            opts["delay"] = l.call_model.delay
            l.call_model.CallEventSequence(cmd_list, lt.apns, **opts)
            cmd_list.append("    call-model name %s" % l.call_model.name)
            cmd_list.append("        ue-set ue-set1")
            cmd_list.append("        call-event-sequence %s" % l.call_model.name)
            cmd_list.append("        call-make rate %s" % l.call_model.make_rate)
            cmd_list.append("        call-break rate %s" % l.call_model.break_rate)
            cmd_list.append("        traffic-model tm-1")
            cmd_list.append("    #exit")
            cmd_list.append("end")
            cmd_string = "echo -e \""
            for c in cmd_list:
                cmd_string += "%s\n" % c
            cmd_string += "\" >> %s" % c_ref.cg_handler.user_config
            self.conn.Run([cmd_string])

    def Start(self):
        self.screen.Create(self.conn)
        self.screen.StartMaster(self.conn, self.initfile)


class Screen(object):

    def __init__(self, name):
        self.name = name
        self.handle = None
 
    def Create(self, conn):
        # check if another instance exists, assuming screen is there
        cmd_string = "screen -list | grep %s" % self.name
        r = conn.Run([cmd_string])
        for line in r.splitlines():
            res_obj = re.search(r'\s+(\d+)\.([\d\w]+)\s+(\([\w]+\))', line)
            if res_obj:
                pid = res_obj.group(1)
                name = res_obj.group(2)
                status = res_obj.group(3)
                logger.debug("Pid: %s, Name: %s, Status: %s" % (pid, name, status))
                if name == self.name:
                    logger.debug("Found screen: %s" % name)
                    instance = "%s.%s" % (pid, name)
                    self.Quit(conn, instance)
        cmd_string = "screen -dmS %s" % self.name
        r = conn.Run([cmd_string])

    def Quit(self, conn, instance):
        cmd_string = "screen -S %s -X quit" % instance
        r = conn.Run([cmd_string])

    def StartMaster(self, conn, file):
        cmd_string = "screen -S %s -p 0 -X eval \'stuff \"cd /localdisk/stargen2; ./stargen -master -init %s\\015\"\'" % (self.name, file)
        r = conn.Run([cmd_string])


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
        self.data_version = None


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
            lattice.id = "%s-%s" % (id, i)
            lattice.tunnel_dev = "tun-%s" % i
            lattice.imsi_fill =  "%03d%s" % (int(id), i)
            lattice.lte_network = lte_net 
            lattice.control_plane.local_ipv4_addr = netaddr.IPNetwork(cl_ipv4)
            lattice.control_plane.local_ipv4_addr.__iadd__(i)
            lattice.control_plane.local_ipv6_addr = netaddr.IPNetwork(cl_ipv6)
            lattice.control_plane.local_ipv6_addr.__iadd__(i)
            lattice.control_plane.remote_ipv4_addr = netaddr.IPNetwork(cr_ipv4)
            lattice.control_plane.remote_ipv6_addr = netaddr.IPNetwork(cr_ipv6)
            lattice.data_plane.local_ipv4_addr = netaddr.IPNetwork(dl_ipv4)
            lattice.data_plane.local_ipv4_addr.__iadd__(i)
            lattice.data_plane.local_ipv6_addr = netaddr.IPNetwork(dl_ipv6)
            lattice.data_plane.local_ipv6_addr.__iadd__(i)
            lattice.data_plane.remote_ipv4_addr = netaddr.IPNetwork(dr_ipv4)
            lattice.data_plane.remote_ipv6_addr = netaddr.IPNetwork(dr_ipv6)
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
            stargen.id = "%s-%s" % (id, i)
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
                # This will need to be passed 
                cgh.user_config = "%s/lattice%s_%s.cfg" % (master.support_lps_dir, id, i)
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
            assert 'ip_version' in next_tag.attrib.keys()
            prot = next_tag.attrib['protocol']
            port = next_tag.attrib['port']
            desc = next_tag.attrib['descriptor']
            vers = next_tag.attrib['ip_version']
        tm = TrafficModel(name)
        tm.protocol = prot
        tm.dst_port = port
        tm.descriptor = desc
        if vers == "ipv4":
            tm.data_version = "data_tx_ipv4 \\\"yes\\\""
        elif vers == "ipv6":
            tm.data_version = "data_tx_ipv6 \\\"yes\\\""
        master.traffic_models.append(tm)
        master.traffic_models_by_name[name] =  tm

    def ParseXml(self):
        tree = ET.parse(self.xml_file)
        root_tag = tree.getroot()
        assert root_tag.tag == "tools"
        assert 'name' in root_tag.attrib.keys()
        assert 'host' in root_tag.attrib.keys()
        name = root_tag.attrib['name']
        host = root_tag.attrib['host']
        master = Master(name)
        # assuming root connection, define host as an object ...
        master.conn = Connect(host, "root", "starent")
        if not master.conn.Open():
            logger.error("Could not connect to master")
            assert False
        logger.info("Connected to Master")
        for next_tag in root_tag:
            if next_tag.tag == "stargen":
                self.__AddStargens(next_tag, master)
            elif next_tag.tag == "traffic_mix":
                self.__AddTrafficMix(next_tag, master)
            elif next_tag.tag == "lattice":
                self.__AddLattices(next_tag, master)
            elif next_tag.tag == "lte_network":
                self.__AddLteNetwork(next_tag, master)
            elif next_tag.tag == "preferences":
                master_folder = next_tag.attrib['master_files']
                init_folder = next_tag.attrib['init_files']
                support_folder = next_tag.attrib['support_files']
                master.masterfile = "%s/%s.cfg" % (master_folder, name)
                master.initfile = "%s/%s.ini" % (init_folder, name)
                master.support_lps_dir = "%s" % support_folder
                cmd_string = "echo > %s" % master.masterfile
                master.conn.Run([cmd_string])
                cmd_string = "echo > %s" % master.initfile
                master.conn.Run([cmd_string])
            else:
                logger.error("Unknown tag %s" % next_tag.tag)
                raise
        return master
