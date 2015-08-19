import pexpect
import datetime
import time
import re
import time
from evolve_log import *

logger = GetLogger()

class Connect(object):

    """Connect to remote host via ssh or telnet and issue commands.
    """

    def __init__(self, host, username, password, **options):
        self.host = host
        self.username = username
        self.password = password
        self.options = options
        self.console_output = "1 - Initiate a regular session"
        self.cfe_break = "Abort Boot by Depressing"
        self.ssh_options = "UserKnownHostsFile /dev/null"
        self.new_key="Are you sure you want to continue connecting \(yes/no\)\?"
        self.passwd="[pP]assword:"
        self.login="([Ll]ast)? [lL]ogin:"
        self.generic_prompt = "([^ \r\n][^\r\n]*[#>\$] ?)$"
        self.prompt = "Prompt Unknown"
        self.line_chew = "([^\r\n]*)[\r\n]+"
        self.child = ""
        self.connection_id = ""

        """This function is called at class creation.
        Inputs:
        host:      - String: hostname where to connect to
        username:  - String: username 
        password:  - String: password
        options:   - Dictionary: optional parameters
        """

    def __Expect(self, t_out=120):

        """This function implements the state machine to get to the 
        prompt, it's to be used only by methods of this class

        Inputs:     - Int: timeout

        Outputs:    - String: everything up to the prompt
        """

        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False 
        retVal = None
        while True:
            self.child = self.connection_id.expect([
                         pexpect.TIMEOUT, 
                         pexpect.EOF, 
                         self.new_key, 
                         self.login, 
                         self.passwd, 
                         self.console_output,
                         self.cfe_break,
                         self.prompt,
                         self.generic_prompt],
                         timeout = t_out)
            if self.child == 0: # Timeout
                self.connection_id.close()
                logger.error("Timeout Expired, Buffer=<%s>" % (self.connection_id.before))
                break
            elif self.child == 1: # EOF
                logger.error("EOF received: Buffer=<%s>" % (self.connection_id.before))
                self.connection_id.close()
                break
            elif self.child == 2: # New key, do you want to continue? Yes
                if self.options.has_key("verbose"):
                    logger.info("New key(before): Buffer=<%s>" % (self.connection_id.before))
                self.connection_id.sendline("yes")
                if self.options.has_key("verbose"):
                    logger.info("New key(after): Buffer=<%s>" % (self.connection_id.after))
            elif self.child == 3: # Login
                if self.options.has_key("verbose"):
                    logger.info("Login detected: Buffer=<%s>" % (self.connection_id.before))
                if (self.connection_id.match.group(1)) == "Last":
                    if self.options.has_key("verbose"):
                        logger.info("Login detected, but it's not a request for username")
                else:
                    self.connection_id.sendline(self.username)
            elif self.child == 4: # Password
                if self.options.has_key("verbose"):
                    logger.info("Password requested: Buffer=<%s>" % (self.connection_id.before))
                self.connection_id.sendline(self.password)
            elif self.child == 5: # Console output
                if self.options.has_key("verbose"):
                    logger.info("Console, multiple selection detected: Buffer=<%s>" % (self.connection_id.before))
                # Choose 1 - Initiate a regular session
                self.connection_id.sendline("1")
            elif self.child == 6: # CFE break
                if self.options.has_key("verbose"):
                    logger.info("Console, request for Abort detected: Buffer=<%s>" % (self.connection_id.before))
                self.connection_id.sendcontrol("c")
            elif self.child == 7: # In, specific prompt found
                # This case is only called after a generic prompt is found, and if the prompt is set
                if self.options.has_key("verbose"):
                    logger.info("Prompt found: Buffer=<%s>" % (self.connection_id.before))
                retVal = self.connection_id.match.group()
                break
            elif self.child == 8: # In, generic prompt found
                if self.options.has_key("verbose"):
                    for line in self.connection_id.before.splitlines():
                        logger.info("%s" % line)
                    logger.info("Generic prompt found: Buffer=<%s>" % (self.connection_id.match.group()))
                # Set prompt, READ: it causes an issue with $, needs escape, comment for now
                #self.prompt = self.connection_id.match.group()
                # Return everything up to the prompt
                retVal = self.connection_id.before
                break
            else:
                if self.options.has_key("verbose"):
                    logger.info("Unexpected index %s: Buffer=<%s>" % (self.child, self.connection_id.before))
                self.connection_id.close()
                break
        return retVal

    def __OpenSsh(self, t_out=120):

        """This function spawns the ssh connection

        Inputs:     - Int: timeout

        Outputs:    - Int: connection id
        """

        options = ""
        if self.options.has_key("port"):
            options += "-p %s" % self.options["port"]
        self.connection_id = pexpect.spawn('ssh -X -o "%s" -l %s %s %s' % (
                             self.ssh_options, self.username, options, self.host))
        return self.connection_id
        
    def __OpenTelnet(self, t_out=120):

        """This function spawns the ssh connection

        Inputs:     - Int: timeout

        Outputs:    - Int: connection id
        """

        port = ""
        if self.options.has_key("port"):
            port = self.options["port"]
        self.connection_id = pexpect.spawn('telnet %s %s' % (
                             self.host, port))
        return self.connection_id

    def Open(self, t_out=60):

        """This function  opens the ssh or telnet connections
        and get to the prompt

        Inputs:     - Int: timeout

        Outputs:    - Bool
        """

        if self.__OpenSsh(t_out) and self.__Expect():
            return True
        if self.__OpenTelnet(t_out) and self.__Expect():
            return True
        logger.error("Could not open connection")
        assert False
    
    def Run(self, cmd_list):

        """This function executes a list of commands
        and returns up to the prompt

        Inputs:     - List: list of commands

        Outputs:    - String: up to the prompt
        """

        if not cmd_list:
            logger.error("Empty Command List") 
            assert False
        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        for line in cmd_list:
            #logger.debug("Before sending: %s", time.clock())
            self.connection_id.sendline(line)
            #logger.debug("After sending: %s", time.clock())
            res = self.__Expect()
            if res:
                error_string = ["(ERROR|Error|error):.*"]
                error_string.append("RTNETLINK answers:(.*)") 
                error_string.append("Unknown command -(.*)") 
                error_string.append("\% Invalid command at \'\^\' marker") 
                for line in res.splitlines():
                    for e in error_string:
                        res_obj = re.search(r'{0}'.format(e), line)
                        if res_obj:
                            logger.error("Error, %s" % res_obj.group())
                            assert False
        return res

    def Close(self):

        """This function close the conn id

        Inputs:     - None

        Outputs:    - None
        """

        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        self.connection_id.close()

    def Chew(self, cmd):

        """This function close the conn id

        Inputs:     - None

        Outputs:    - None
        """

        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        self.connection_id.sendline(cmd)
        while True:
            self.child = self.connection_id.expect([
                         pexpect.TIMEOUT, 
                         pexpect.EOF, 
                         self.line_chew])
            if self.child == 0: # Timeout
                logger.error("Timeout Expired, Buffer=<%s>" % (self.connection_id.before))
            elif self.child == 1: 
                self.connection_id.close()
                logger.error("EOF received: Buffer=<%s>" % (self.connection_id.before))
                assert False
            elif self.child == 2: # In
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                logger.info("%s %s" % (st, self.connection_id.match.group(1)))
            else:
                self.connection_id.close()
                logger.error("UNEXPECTED: %s" % (self.connection_id.before))
                assert False

