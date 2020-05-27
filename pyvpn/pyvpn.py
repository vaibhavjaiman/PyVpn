from pyvpn.source.providers import PaloAlto
from pyvpn.source.vpn import Vpn
from pyvpn.source.client import Client


class PyVpn(Vpn):

    def __init__(self, provider=None, key=None, username=None, password=None, token=None, config=None, vpn_gateway=None, host=None, debug=False, whitelists=None):
        """

        :param provider: Provider for initiating connection like Paloalto,Juniper,Cisco
        :param key: (Optional) , Used for decrypting the encrypted password
        :param username: username for vpn
        :param password: password for vpn , use "crypt_" if you are using encrypted password
        :param token: Used for notification purposes , Push - ? , sms - ? , call - ?
        :param config: absoulute path for the PyVpn.yaml config file
        :param vpn_gateway: preffered vpn gateway
        :param host: public vpn gateway endpoint
        :param debug: default False
        """
        super(PyVpn, self).__init__(key, username, password, token, config, vpn_gateway, host, whitelists)
        self._provider = provider
        self.debug = debug

    @property
    def provider(self):
        """
        :return: provider to be used
        """
        _provider_allowed = ["paloalto"]

        if self._provider is None:
            # default VPN gateway
            self._provider = "paloalto"

        if self._provider in _provider_allowed:
            return self._provider
        else:
            raise SystemExit(Exception(("Error - Acceptable vpn providers are : {}".format(_provider_allowed))))

    @property
    def start(self):
        """connect to the relevant vpn provider which is for now restricted to PaloAlto
        Future addition for other VPN gateway like Ciso , Juniper etc
        Once VPN is connected it's set to wait indefinetely till the method Stop is called.
        """
        try:
            if self.provider == "paloalto":
                session = PaloAlto(debug=self.debug,
                                   username=self.username,
                                   password=self.password,
                                   token=self.token,
                                   vpn_gateway=self.vpn_gateway,
                                   host=self.host)
                session = session.connect
                session.wait()

            else:
                # Pending dev. for other providers
                pass
        except KeyboardInterrupt:
            self.stop

    @property
    def stop(self):
        """stop the connection gracefully"""
        Client().disconnect