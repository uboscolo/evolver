from nose.tools import *
import os
from evolver.stargen import *

def setup():
    try:
        if os.path.exists("/tmp/evolve_tools.log"):
            os.remove("/tmp/evolve_tools.log")
    except:
        raise

def teardown():
    try:
        pass
    except:
        raise

def test_1():
    """Run Test 1"""
    try:
        Logger("extensive", "/tmp/evolve_tools.log")
        for i in range(3,8)+range(16,21):
            try:
                fname = "tests/functest/luto%s.xml" % i 
                xml_file = open(fname, "r")
                p = ToolParser(xml_file)
                master = p.ParseXml()
                master.CreateServers()
                master.CreateClients()
                master.CreateLatticeConfigs()
                master.Start()
            except IOError:
                print "Could not open file"
                raise
    except IOError:
        print "Logger error"
        raise
