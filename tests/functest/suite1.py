from nose.tools import *
import os
from evolver.evolver import *

def setup():
    try:
        if os.path.exists("/tmp/evolve_suite1.log"):
            os.remove("/tmp/evolve_suite1.log")
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
        Logger("extensive", "/tmp/evolve_suite1.log")
        xml_file = open("tests/functest/suite1.xml", "r")
        p = Parser(xml_file)
        sys = p.ParseXml()
        sys.Display()
    except IOError:
        print "Could not open file"
        raise

