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
 
    def CallEventSequence(self, apns, **options):
        if self.name == "vzw-hsgw-make-break-1":
            logger.debug("Call Sequence not implemented")
            assert False
        elif self.name == "vzw-sgw-make-break-1":
            logger.debug("Call Sequence not implemented")
            assert False
        elif self.name == "vzw-sgw-make-break-2":
            assert len(apns) == 2
            logger.debug("    call-event-sequence name %s" % self.name)
            logger.debug("        initial-attach lte sgw-set sgw-1 apn %s" % apns[0].name)
            logger.debug("        new-pdn apn %s delay 1" % apns[1].name)
            logger.debug("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            logger.debug("        break-call delay 1")
            logger.debug("        iterate-count unlimited")
            logger.debug("        make-call apn %s delay 1" % apns[0].name)
            logger.debug("        new-pdn apn %s delay 1" % apns[1].name)
            logger.debug("        delete-pdn apn internet-1 delay %s" % options["delay"])
            logger.debug("        break-call delay 1")
            logger.debug("    #exit")
        elif self.name == "vzw-hsgw-make-break-2":
            assert len(apns) == 2
            logger.debug("    call-event-sequence name %s" % self.name)
            logger.debug("        initial-attach ehrpd hsgw-set hsgw-1 apn %s" % apns[0].name)
            logger.debug("        new-pdn apn %s delay 1" % apns[1].name)
            logger.debug("        delete-pdn apn internet-1 delay %s" % options["initial_delay"])
            logger.debug("        break-call delay 1")
            logger.debug("        iterate-count unlimited")
            logger.debug("        make-call apn %s delay 1" % apns[0].name)
            logger.debug("        new-pdn apn %s delay 1" % apns[1].name)
            logger.debug("        delete-pdn apn internet-1 delay %s" % options["delay"])
            logger.debug("        break-call delay 1")
            logger.debug("    #exit")
        else:
            logger.debug("Call Sequence not implemented")
            assert False
