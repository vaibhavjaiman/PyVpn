import subprocess
import netifaces
from pyvpn.source.vpn import Vpn


class Routes(object):

    def __init__(self):
        """Catching the DNS lookup before initiating VPN connection
        This will result Error for any invalid dns entry """
        self.native_gateway_cached = self.gateway
        self.__whitelists_cached = Vpn().whitelists

    @property
    def gateway(self):
        """
        :return: current gateway address
        """
        return tuple(netifaces.gateways()['default'].values())[0][0]

    @property
    def getroutes(self):
        """
        add routes based on OS distros , Currently supports MAC
        :return: routes based on the user system
        """
        return [("sudo route add {} {}".format(ip, self.gateway)) for ip in self.__whitelists_cached]


    def addroutes(self):
        """add the routes post successful vpn connection
           :param native_gateway is the default system pre-vpn gateway which should be used for passing generic traffic
        """
        for route in self.getroutes:
            try:
                subprocess.call(route, shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            except Exception as error:
                print("Error {} Occurred while adding route '{}'".format(error, route))

        # Delete default route added post connecting vpn
        subprocess.call("sudo route delete default {}".format(self.gateway), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        # Add/Update System default route
        subprocess.call("sudo route add default {}".format(self.native_gateway_cached), shell=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)