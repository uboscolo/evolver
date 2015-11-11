#!/usr/bin/env python

import sys
import getpass
import optparse
from connect2 import *

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
    opts, remainder = parser.parse_args()

    if len(remainder) != 1:
        parser.error("wrong number of arguments")
    hostname = remainder[0]
  
    options = {}
    cmd_list = []
    if opts.verbose:
        options["verbose"] = opts.verbose
    username = "staradmin"
    if opts.username:
        username = opts.username
    password = "starent"
    if opts.password:
        password = opts.password
    cmd_list.append("show version")
    cmd_list.append("show card table")
    cmd_list.append("show port table")
    cmd_list.append("show hardware version")
    if opts.cmd_list:
        cmd_list = []
        cmd_list.append(opts.cmd_list)

    #options = { 'class' : 'mitg' }
    options["class"] = "mitg"
    c = Connect(hostname, username, password, **options)
    c.Open()
    r = c.Run(cmd_list)
    print("{0}".format(r))
    c.Close()

if __name__ == "__main__":
    main(sys.argv[1:])
