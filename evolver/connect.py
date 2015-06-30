import pexpect
import datetime
import time
import re
from evolve_log import *

logger = GetLogger()

class Connect(object):

    def __init__(self, host, username, password, **options):
        self.host = host
        self.username = username
        self.password = password
        self.options = options
        self.ssh_options = "UserKnownHostsFile /dev/null"
        self.new_key="Are you sure you want to continue connecting \(yes/no\)\?"
        self.passwd="[pP]assword:"
        self.login="([Ll]ast)? [lL]ogin:"
        self.generic_prompt = "([^ \r\n][^\r\n]*[#>\$] ?)$"
        self.prompt = "Prompt Unknown"
        self.line_chew = "([^\r\n]*)[\r\n]+"
        self.child = ""
        self.connection_id = ""

    def __Expect(self):
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
                         self.prompt,
                         self.generic_prompt])
            if self.child == 0: # Timeout
                if self.options.has_key("verbose"):
                    logger.info("TIMEOUT: %s" % (self.connection_id.before))
                self.connection_id.close()
                logger.error("TIMEOUT: %s" % (self.connection_id.before))
                break
            elif self.child == 1: 
                logger.error("EOF: %s" % (self.connection_id.before))
                self.connection_id.close()
                break
            elif self.child == 2: # New key, do you want to continue? Yes
                if self.options.has_key("verbose"):
                    logger.info("NEW_KEY: %s" % (self.connection_id.before))
                self.connection_id.sendline("yes")
                if self.options.has_key("verbose"):
                    logger.info("NEW_KEY: %s" % (self.connection_id.after))
            elif self.child == 3: # Login
                if self.options.has_key("verbose"):
                    logger.info("LOGIN: %s" % (self.connection_id.before))
                if (self.connection_id.match.group(1)) == "Last":
                    if self.options.has_key("verbose"):
                        logger.info("LOGIN: Not a request for username")
                else:
                    self.connection_id.sendline(self.username)
                if self.options.has_key("verbose"):
                    logger.info("LOGIN: %s" % (self.connection_id.after))
            elif self.child == 4: # Password
                if self.options.has_key("verbose"):
                    logger.info("PASSWORD: %s" % (self.connection_id.before))
                self.connection_id.sendline(self.password)
                if self.options.has_key("verbose"):
                    logger.info("PASSWORD: %s" % (self.connection_id.after))
            elif self.child == 5: # In
                if self.options.has_key("verbose"):
                    logger.info("PROMPT: %s" % (self.connection_id.before))
                logger.debug("%s" % (self.connection_id.match.group()))
                retVal = self.connection_id.match.group()
                break
            elif self.child == 6: # In
                logger.debug("%s" % (self.connection_id.before))
                if self.options.has_key("verbose"):
                    logger.info("GENERIC PROMPT: %s" % (self.connection_id.match.group()))
                # causes an issue with $, comment for now
                #self.prompt = self.connection_id.match.group()
                if self.options.has_key("verbose"):
                    logger.info("GENERIC PROMPT: %s" % (self.connection_id.after))
                retVal = self.connection_id.before
                #retVal = self.connection_id.match.group()
                #retVal = self.connection_id.after
                break
            else:
                if self.options.has_key("verbose"):
                    logger.info("UNEXPECTED: %s" % (self.connection_id.before))
                self.connection_id.close()
                logger.error("UNEXPECTED: %s" % (self.connection_id.before))
                break
        return retVal

    def __OpenSsh(self):
        options = ""
        if self.options.has_key("port"):
            options += "-p %s" % self.options["port"]
        self.connection_id = pexpect.spawn('ssh -X -o "%s" -l %s %s %s' % (
                             self.ssh_options, self.username, options, self.host))
        return self.connection_id
        
    def __OpenTelnet(self):
        port = ""
        if self.options.has_key("port"):
            port = self.options["port"]
        self.connection_id = pexpect.spawn('telnet %s %s' % (
                             self.host, port))
        return self.connection_id

    def Open(self):
        if self.__OpenSsh() and self.__Expect():
            return True
        if self.__OpenTelnet() and self.__Expect():
            return True
        logger.error("Could not open connection")
        assert False
    
    def Run(self, cmd_list):
        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        for line in cmd_list:
            self.connection_id.sendline(line)
            res = self.__Expect()
            for line in res.splitlines():
                #res_obj =  re.search(r'.*Device (.*) does not exist', line)
                #if res_obj:
                #    logger.error("Error, %s" % res_obj.group())
                #    assert False
                res_obj =  re.search(r'(ERROR|Error|error):.*', line)
                if res_obj:
                    logger.error("Error, %s" % res_obj.group())
                    assert False
                res_obj =  re.search(r'RTNETLINK answers:(.*)', line)
                if res_obj:
                    logger.error("Error, %s" % res_obj.group())
                    assert False
                #res_obj =  re.search(r'.*Invalid command at', line)
                #if res_obj:
                #    logger.error("Error, %s" % res_obj.group())
                #    assert False
        return res

    def Close(self):
        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        self.connection_id.close()

    def Chew(self, cmd):
        self.connection_id.sendline(cmd)
        if not self.connection_id:
            logger.error("Connection is not open %s" % self.connection_id)
            assert False
        while True:
            self.child = self.connection_id.expect([
                         pexpect.TIMEOUT, 
                         pexpect.EOF, 
                         self.line_chew])
            if self.child == 0: # Timeout
                if self.options.has_key("verbose"):
                    logger.info("TIMEOUT: %s" % (self.connection_id.before))
            elif self.child == 1: 
                if self.options.has_key("verbose"):
                    logger.info("EOF: %s" % (self.connection_id.before))
                self.connection_id.close()
                logger.error("EOF: %s" % (self.connection_id.before))
                self.connection_id.close()
                assert False
            elif self.child == 2: # In
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                logger.info("%s %s" % (st, self.connection_id.match.group(1)))
            else:
                if self.options.has_key("verbose"):
                    logger.info("UNEXPECTED: %s" % (self.connection_id.before))
                self.connection_id.close()
                logger.error("UNEXPECTED: %s" % (self.connection_id.before))
                assert False

