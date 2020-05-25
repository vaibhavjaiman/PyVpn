import os
import time
from signal import SIGTERM
from pyvpn.source.vpn import Vpn


class Client(object):

    @property
    def disconnect(self):
        """
        :return: True, disconnect the connection from the vpn client
        """
        try:
            with open(Vpn().pidfile, "r") as file:
                pid = int(file.read())
            if pid:
                os.kill(pid, SIGTERM)
                time.sleep(0.5)
                if os.path.exists(Vpn().pidfile):
                    os.remove(Vpn().pidfile)
                print("Success: VPN has been disconnected Properly")
                return True

        except TypeError as error:
            raise SystemExit(Exception(("TypeError has occurred {}".format(error))))

        except FileNotFoundError:
            raise SystemExit(Exception("FileNotFoundError : {} doesn't exist!! Close connection manually".format(Vpn().pidfile)))

        except ProcessLookupError:
            raise SystemExit(Exception("ProcessLookupError : ProcessID {} not found".format(pid)))