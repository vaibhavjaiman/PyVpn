import pexpect
import sys
import time
import os
from pyvpn.source.vpn import Vpn
from pyvpn.source.routes import Routes


class Providers(object):

    def __init__(self, username, password, token, vpn_gateway, host, debug=False):
        self.debug = debug
        self.username = username
        self.password = password
        self.token = token
        self.vpn_gateway = vpn_gateway
        self.host = host

    @property
    def checkPidFile(self):
        if os.path.exists(Vpn().pidfile):
            raise SystemExit(Exception("FileExistsError - {} file already exist".format(Vpn().pidfile)))
        else:
            return True


class PaloAlto(Providers):

    def __init__(self, username, password, token, vpn_gateway, host, debug=False):
        super(PaloAlto, self).__init__(username=username,
                                       password=password,
                                       token=token,
                                       vpn_gateway=vpn_gateway,
                                       host=host,
                                       debug=debug)

        """
        Initializing the Route Class for catching before VPN Connect native_gateway and whitelisted address
        """
        self.routes = Routes()

    @property
    def connect(self):

        """openconnect is used for connecting to paloalto protocol <gp> using pexpect
        the session variable can also be made to wait indefinetely via
        session.expect([pexpect.EOF], timeout=None) or session.wait()
        :return session object
        """

        if self.checkPidFile:
            try:
                session = pexpect.spawn("sudo openconnect --protocol=gp -u {} {}".format(self.username, self.host))
                if self.debug:
                    session.logfile = sys.stdout.buffer
                session.expect('Password.*')
                session.sendline(self.password)
                session.expect('Password.*')
                session.sendline(self.password)
                session.expect('.*GATEWAY.*')
                session.sendline(self.vpn_gateway)
                session.expect('.*Challenge.*')
                session.sendline(self.token)
                "Successfully connected to vpn"
                session.expect('.*Connected.*')
                time.sleep(1)
                session.expect('.*tunnel connected.*')
                self.routes.addroutes()
                with open(Vpn().pidfile, "w+") as myfile:
                    myfile.write(str(os.getpid()))
                return session

            except pexpect.EOF:
                raise SystemExit(Exception("Connection Termination Error : pexpect module reached End of File"))
            except pexpect.TIMEOUT:
                raise SystemExit(Exception("Timeout Error - Probably.. User failed to approve supplied Challenge"))
            except Exception as error:
                raise SystemExit(Exception("Unhandled Exception Error - {}".format(error)))
