import pexpect
import netifaces
import yaml
import os
import time
import sys
import dns.resolver
import subprocess
import base64
from signal import SIGTERM
from concurrent.futures import ThreadPoolExecutor

class Crypt:

    def __init__(self, config=None, key=None):
        self._key = key
        self._config = config
        try:
            with open(self.config, "r") as file:
                self.cfg = yaml.load(file, Loader=yaml.BaseLoader)
        except IOError:
            raise SystemExit("Error:Unable to read file {}".format(self.config))

        except FileNotFoundError:
            raise SystemExit("Error: File {} doesn't exist".format(self.config))

    @property
    def config(self):
        if self._config is None:
            return os.path.splitext(__file__)[0] + ".yaml"
        else:
            return self._config

    def encrypt(self, password):
        enc = []
        for i in range(len(password)):
            key_c = self.key[i % len(self.key)]
            enc_c = chr((ord(password[i]) + ord(key_c)) % 256)
            enc.append(enc_c)
        return base64.urlsafe_b64encode("".join(enc).encode()).decode()

    @property
    def key(self):
        try:
            if not self._key:
                return self.cfg["key"]
            else:
                return self._key
        except:
            raise SystemExit("Error:Key cannot be fetched")

    def decrypt(self, password):
        dec = []
        password = base64.urlsafe_b64decode(password).decode()
        for i in range(len(password)):
            key_c = self.key[i % len(self.key)]
            dec_c = chr((256 + ord(password[i]) - ord(key_c)) % 256)
            dec.append(dec_c)
        return "".join(dec)


class PyVpn(Crypt):

    def __init__(self, config=None, pidfile=None, username=None, password=None, timeout=300, debug=False):
        super().__init__(config=config)
        self._username = username
        self._password = password
        self.timeout = timeout
        self.debug = debug
        self._pidfile = pidfile
        self.native_gateway = self.gateway # default gateway before VPN connect

    @property
    def checkPidFile(self):
        if os.path.exists(self.pidfile):
            raise SystemExit("{} file already exist".format(self.pidfile))
        else:
            return True

    @property
    def username(self):
        if not self._username:
            return self.cfg["vpn"]["username"]
        else:
            return self._username

    @property
    def password(self):
        if not self._password:
            return self.decrypt(self.cfg["vpn"]["password"])
        else:
            return self._username

    @property
    def pidfile(self):
        if self._pidfile is None:
            return os.path.splitext(__file__)[0] + ".pid"

    @property
    def host(self):
        return self.cfg["vpn"]["host"]

    @property
    def vpn_gateway(self):
        return self.cfg["vpn"]["gateway"][0]

    @property
    def token(self):
        return list(self.cfg["vpn"]["token"].values())[0]

    @property
    def gateway(self):
        return tuple(netifaces.gateways()['default'].values())[0][0]

    @property
    def connect(self):
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
                # Connected to VPN
                session.expect('.*Connected.*')
                time.sleep(1)
                session.expect('.*tunnel connected.*')
                self.addroutes()
                with open(self.pidfile, "w+") as myfile:
                    myfile.write(str(os.getpid()))
                # return session
                # session.expect([pexpect.EOF], timeout=None)
                session.wait()

            except pexpect.EOF:
                raise SystemExit("Error Occurred - pexpect EOF")
            except pexpect.TIMEOUT:
                raise SystemExit("Error Occurred - Connection timeout")
            except Exception as error:
                raise SystemExit("Unhandled Exception Occurred - {}".format(error))

    @property
    def disconnect(self):
        try:
            with open(self.pidfile, "r") as file:
                pid = int(file.read())
        except FileNotFoundError:
            raise SystemExit("pid file {} doesn't exist, Close connection by killing process".format(self.pidfile))
        try:
            if pid:
                os.kill(pid, SIGTERM)
                time.sleep(0.5)
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            print("Success: VPN has been disconnected Properly")
            sys.exit(1)
        except TypeError as error:
            print(error)
        except Exception as error:
            print("Unhandled exception occured {}".format(error))

    def getipaddress(self, hostname):
        try:
            return dns.resolver.query(hostname, 'A').rrset.items[0].address
        except dns.exception.DNSException as error:
            print("Error resolving hostname '{}': {}".format(hostname,error))
        except dns.exception.Timeout as error:
            print("Timeout while resolving hostname '{}': {}".format(hostname,error))

    @property
    def whitelists(self, maxworker=8):
        with ThreadPoolExecutor(max_workers=maxworker, thread_name_prefix="dns") as executor:
            return {"{}/32".format(ip) for hostname, ip in zip(self.cfg["whitelists"], executor.map(self.getipaddress, self.cfg["whitelists"]))}

    @property
    def getroutes(self):
        return [("sudo route add {} {}".format(ip, self.gateway)) for ip in self.whitelists]

    def addroutes(self):
        for route in self.getroutes:
            try:
                subprocess.call(route, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as error:
                print("Exception:{}".format(error))

        # Delete default route added post connecting vpn
        subprocess.call("sudo route delete default {}".format(self.gateway), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        subprocess.call("sudo route add default {}".format(self.native_gateway), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
