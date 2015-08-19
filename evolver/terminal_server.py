import sys
import os
import time
from evolve_log import *
from connect import *

logger = GetLogger()

class TerminalServer(object):

    """Connect to terminal server via ssh.
    """

    def __init__(self, host, username):
        try: 
            self.pid = os.fork()
            if self.pid > 0:
                # parent process, return and keep running
                return
        except OSError, e:
            logger.error("fork #1 fail: %d (%s)" % (e.errno, e.strerror))
            assert False
        # group
        os.setsid()
        options = {}
        self.conn = Connect(host, username, "", **options)
        self.conn.Open()

        """This function is called at class creation. It forks a child,
        where all its methods should be executed
      
        Inputs:
        host:      - String: hostname where to connect to
        username:  - String: username 
        """

    def Run(self, cmd_list):

        """This function executes a list of commands
        through a connect object and returns up to the prompt

        Inputs:     - List: list of commands

        Outputs:    - String: up to the prompt
        """

        if not self.pid:
            logger.debug("Sending %s (pid %d)" % (cmd_list, os.getpid()))
            return self.conn.Run(cmd_list)

    def Sendline(self, cmd):

        """This function send a command through a connect object

        Inputs:     - String: command

        Outputs:    - None
        """

        if not self.pid:
            logger.debug("Sending %s (pid %d)" % (cmd, os.getpid()))
            self.conn.connection_id.sendline(cmd)

    def Close(self):

        """This function closes the connect object connection
        and exits

        Inputs:     - None

        Outputs:    - None
        """

        if not self.pid:
            logger.debug("Closing ... (pid %d)" % (os.getpid()))
            self.conn.Close()
            os._exit(os.EX_OK)



