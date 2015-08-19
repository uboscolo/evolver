#!/usr/bin/env python

import sys
import os
import time
import getpass
import optparse
from connect import *
from terminal_server import *
from evolve_log import *


#def spawnTsConnection(host, username):
#    try: 
#        pid = os.fork() 
#        if pid > 0:
#            # parent process, return and keep running
#            return
#    except OSError, e:
#        print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror) 
#        sys.exit(1)
#    # group
#    os.setsid()
#    # do second fork
#    try: 
#        pid = os.fork() 
#        if pid > 0:
#            # exit from second parent
#            sys.exit(0) 
#    except OSError, e: 
#        print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror) 
#        sys.exit(1)
#
#    options = {}
#    c = Connect(host, username, "", **options)
#    c.Open()
#    print "Found Cfe"
#    c.Run(["cli"])
#    c.Run(["help upgrade"])
#    c.connection_id.sendline("boot\n")
#
#    # all done
#    os._exit(os.EX_OK)


def main(argv):
    parser = optparse.OptionParser(usage="usage: %prog [options] target")
    parser.add_option('-v', '--verbose',
                  dest="verbose",
                  default=False,
                  help="turn on verbosity",
                  action="store_true"
                  )
    parser.add_option('-u', '--username',
                  dest="username",
                  help="username",
                  action="store"
                  )
    parser.add_option('-p', '--password',
                  dest="password",
                  help="password",
                  action="store"
                  )
    parser.add_option('-c', '--command_list',
                  dest="cmd_list",
                  help="command list",
                  action="store"
                  )
    parser.add_option('--terminal_server_connection1',
                  dest="conn1",
                  help="terminal server connection 1",
                  action="store"
                  )
    parser.add_option('--terminal_server_connection2',
                  dest="conn2",
                  help="terminal server connection 2",
                  action="store"
                  )
    opts, remainder = parser.parse_args()

    if len(remainder) != 1:
        parser.error("wrong number of arguments")
    hostname = remainder[0]

    Logger("extensive", "/tmp/run_cmd.log")
  
    options = {}
    cmd_list = []
    ts1 = None
    ts2 = None
    if opts.verbose:
        options["verbose"] = opts.verbose
    username = "staradmin"
    if opts.username:
        username = opts.username
    password = "starent"
    if opts.password:
        password = opts.password
    cmd_list.append("show version")
    if opts.cmd_list:
        cmd_list = []
        cmd_list.append(opts.cmd_list)
    if opts.conn1:
        uname1 = opts.conn1.split("@")[0]
        ts1 = opts.conn1.split("@")[1]
    if opts.conn2:
        uname2 = opts.conn2.split("@")[0]
        ts2 = opts.conn2.split("@")[1]

    c = Connect(hostname, username, password, **options)
    c.Open()
    print "Found prompt, reload"
    c.connection_id.sendline("reload -n\n")
    c.Close()
    
    if ts2:
        t2 = TerminalServer(ts2, uname2) 
        t2.Run(["cli"])
        t2.Run(["help upgrade"])
        t2.Sendline("boot\n")
        t2.Close()

    if ts1:
        t1 = TerminalServer(ts1, uname1) 
        t1.Run(["cli"])
        t1.Run(["help upgrade"])
        t1.Sendline("boot\n")
        t1.Close()

if __name__ == "__main__":
    main(sys.argv[1:])
