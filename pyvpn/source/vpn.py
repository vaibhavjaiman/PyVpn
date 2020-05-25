import yaml
from pyvpn.source.crypt import Crypt
from pathlib import Path
import os
import errno
from socket import gethostbyname, gaierror, timeout
from concurrent.futures import ThreadPoolExecutor


class Vpn(object):

    def __init__(self, key=None, username=None, password=None, token=None, config=None, vpn_gateway=None, host=None, whitelists=[]):
        """

        :param key:
        :param username:
        :param password:
        :param token:
        :param config: configuration absolute path pyvpn.yaml , if absent data will be read from the cwd()
        :param vpn_gateway: preferred vpn gateway based on the priority
        :param host:
        """
        self._key = key
        self._username = username
        self._password = password
        self._token = token
        self._config = config
        self._host = host
        self._vpn_gateway = vpn_gateway
        self._whitelists = whitelists

    @property
    def key(self):
        """
        :return: key that will be used for decrypting password
        """
        try:
            if self._key is None:
                self._key = self.readconfig["key"]
            return self._key

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'key' : Validate {} or supply manually".format(self.config)))

    @property
    def config(self):
        """

        :return: the path of the configuration file
        """

        if self._config is None:
            self._config = "".join((str(Path.home()).rstrip("/"), "/.pyvpn.yaml"))

        if os.path.exists(self._config):
            return self._config
        else:
            raise SystemExit(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self._config))

    @property
    def readconfig(self):
        """
        :return: loads the configuration file in readconfig object
        """
        try:
            with open(self.config, "r") as file:
                readconfig = yaml.load(file, Loader=yaml.BaseLoader)
            return readconfig

        except yaml.YAMLError as error:
            raise SystemExit(Exception("Error {} : Unable to read configuration file {}").format(error, self.config))

        except IOError:
            raise SystemExit(Exception("Error: Unable to read configuration file {}".format(self.config)))

    @property
    def username(self):
        """

        :return: username in clear text
        """
        try:
            if self._username is None:
                self._username = self.readconfig["vpn"]["username"]
            return self._username

        except TypeError as error:
            raise SystemExit(Exception("Error - Unable to fetch value for 'vpn.username' : {}".format(error)))

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'vpn.username' : Validate {} or supply manually".format(self.config)))

    @property
    def password(self):
        """
        :return: password in clear text
        """
        try:
            if self._password is None:
                self._password = self.readconfig["vpn"]["password"]

            if "crypt_" in self._password:
                self._password = Crypt().decrypt(password=str(self._password).split("_")[1], key=self.key)

            return self._password

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'vpn.password' : Validate {} or supply manually".format(self.config)))

    @property
    def pidfile(self):
        """
        :return: absoulute path where pid of the vpn process will be written
        """
        return "".join((str(Path.home()).rstrip("/"), "/pyvpn.pid"))

    @property
    def host(self):
        """
        :return: url for the vpn host address
        """
        try:
            if self._host is None:
                self._host = self.readconfig["vpn"]["host"]

            if gethostbyname(self._host):
                return self._host

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'vpn.host' : Validate {} or supply manually".format(self.config)))

        except gaierror:
            raise SystemExit(Exception("Error - Unable to DNS resolve '{}' ".format(self._host)))

    @property
    def token(self):
        """
        :return: token value for duo-factor authentication
        """
        try:
            _token_allowed = ['1', '2', '3']
            if self._token is None:
                self._token = str(list(self.readconfig["vpn"]["token"].values())[0])

            if self._token in _token_allowed:
                return self._token
            else:
                raise SystemExit(Exception("Error - Invalid token value {} of type {} supplied, Allowed token values of type Int {}".format(self._token, type(self._token), _token_allowed)))

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'token' : Validate {} or supply manually".format(self.config)))

    @property
    def vpn_gateway(self):
        try:
            if self._vpn_gateway is None:
                self._vpn_gateway = self.readconfig["vpn"]["gateway"][0]
            return self._vpn_gateway

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'token' : Validate {} or supply manually".format(self.config)))

    def getipaddress(self, hostname):
        """
        :param hostname: domainname or ipaddress which needs is to be route via vpn gateway
        :return: the ipaddress and the subnet as string
        """
        try:
            #default netmask value
            netmask = "32"
            if hostname.count("/") == 1:
                hostname, netmask = hostname.split("/")

            return "/".join((gethostbyname(hostname), netmask))

        except gaierror:
            print("Warning!! - Skipping host '{}' - Unable to resolve".format(hostname))

        except timeout:
            print("Warning!! - Skipping host '{}' - Query got Timeout".format(hostname))

        except Exception as error:
            print("Warning!! - Skipping host '{}' - Unhandled exception {}".format(hostname, error))

    @property
    def whitelists(self):
        """
        :return: the list of IPs that need to be bypassed based on host addresses / IPaddress / subnet
        """
        try:
            if not self._whitelists:
                self._whitelists = self.readconfig["whitelists"]

            with ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns") as executor:
                    self._whitelists = {"".join(ip)
                                        for hostname, ip in zip(self._whitelists, executor.map(self.getipaddress, self._whitelists))
                                        if ip is not None}
            return self._whitelists

        except KeyError:
            raise SystemExit(Exception("Error - Unreadable value 'whitelists' : Validate {} or supply manually".format(self.config)))