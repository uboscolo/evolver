from evolve_log import *

logger = GetLogger()

class Lattice(object):

    def __init__(self):
        self.id = None
        self.host = None
        self.affinity = None
        self.vr = None
        self.num_instances = None
        self.tunnel_dev = None
        self.lte_network = None
        self.control_plane = Network()
        self.data_plane = Network()
        self.call_model = None


class LteNetwork(object):

    def __init__(self, name):
        self.name = name
        self.mcc = None
        self.mnc = None
        self.tac = None
        self.apns = [ ]

class Network(object):

    def __init__(self):
        self.local_ipv4_addr = None
        self.local_ipv6_addr = None
        self.remote_ipv4_addr = None
        self.remote_ipv6_addr = None

class Apn(object):

    def __init__(self, name):
        self.name = name
        self.type = None
        self.qci = None
        self.arp = None
        self.pec = None

class CallModel(object):

    def __init__(self, name):
        self.name = name
        self.count = None
        self.make_rate = 0
        self.break_rate = 0
        self.initial_delay = 0
        self.delay = 0
        self.options = { }
 
    def CallEventSequence(self, cmd_list, apns, **options):
        if self.name == "vzw-hsgw-make-break-1":
            logger.debug("Call Sequence not implemented")
            assert False
        elif self.name == "vzw-sgw-make-break-1":
            logger.debug("Call Sequence not implemented")
            assert False
        elif self.name == "vzw-sgw-static-2":
            assert len(apns) == 2
            cmd_list.append("    call-event-sequence name %s" % self.name)
            cmd_list.append("        initial-attach lte sgw-set sgw-1 apn %s" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
            cmd_list.append("    #exit")
        elif self.name == "vzw-sgw-make-break-2":
            assert len(apns) == 2
            cmd_list.append("    call-event-sequence name %s" % self.name)
            cmd_list.append("        initial-attach lte sgw-set sgw-1 apn %s" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
            cmd_list.append("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            cmd_list.append("        break-call delay 1")
            cmd_list.append("        iterate-count unlimited")
            cmd_list.append("        make-call apn %s delay 1" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
            cmd_list.append("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            cmd_list.append("        break-call delay 1")
            cmd_list.append("    #exit")
        elif self.name == "vzw-hsgw-static-2":
            assert len(apns) == 2
            cmd_list.append("    call-event-sequence name %s" % self.name)
            cmd_list.append("        initial-attach ehrpd hsgw-set hsgw-1 apn %s" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
        elif self.name == "vzw-hsgw-make-break-2":
            assert len(apns) == 2
            cmd_list.append("    call-event-sequence name %s" % self.name)
            cmd_list.append("        initial-attach ehrpd hsgw-set hsgw-1 apn %s" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
            cmd_list.append("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            cmd_list.append("        break-call delay 1")
            cmd_list.append("        iterate-count unlimited")
            cmd_list.append("        make-call apn %s delay 1" % apns[0].name)
            cmd_list.append("        new-pdn apn %s delay 1" % apns[1].name)
            cmd_list.append("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            cmd_list.append("        break-call delay 1")
            cmd_list.append("    #exit")
        else:
            logger.debug("Call Sequence not implemented")
            assert False
