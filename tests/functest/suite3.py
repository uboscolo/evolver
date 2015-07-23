from nose.tools import *
import os
from evolver.evolve import *

def setup():
    try:
        if os.path.exists("/tmp/evolve_suite3.log"):
            os.remove("/tmp/evolve_suite3.log")
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
        Logger("extensive", "/tmp/evolve_suite3.log")
        xml_file = open("tests/functest/suite3.xml", "r")
        p = ToolParser(xml_file)
        master = p.ParseXml()
        master.CreateServers()
        master.CreateClients()
        master.CreateLatticeConfigs()
    except IOError:
        print "Could not open file"
        raise