from nose.tools import *
import os
from evolver.evolve import *

def setup():
    try:
        if os.path.exists("/tmp/evolve_topology.log"):
            os.remove("/tmp/evolve_topology.log")
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
        Logger("extensive", "/tmp/evolve_topology.log")
        xml_file = open("tests/functest/topology.xml", "r")
        p = Parser(xml_file)
        sys = p.ParseXml()
        sys.Display()
        sys.CheckConnectivity()
        sys.CheckRouting()
    except IOError:
        print "Could not open file"
        raise
