import base64
import random
import string


class Crypt:

    def encrypt(self, password, key):
        """
        :param password: password that needs to be encrypted
        :param key: key used for encrypting the password
        :return: encrypted password
        """
        try:
            enc = []
            for i in range(len(password)):
                key_c = key[i % len(key)]
                enc_c = chr((ord(password[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            return base64.urlsafe_b64encode("".join(enc).encode()).decode()
        except Exception as error:
            raise SystemExit(Exception("Error - {} Unhandled Exception".format(error)))

    def decrypt(self, password, key):
        """
        :param password: crypt password which needs to be decrpted
        :param key: key to be used for decryption
        :return: clear text password
        """

        try:
            dec = []
            password = base64.urlsafe_b64decode(password).decode()
            for i in range(len(password)):
                key_c = key[i % len(key)]
                dec_c = chr((256 + ord(password[i]) - ord(key_c)) % 256)
                dec.append(dec_c)
            return "".join(dec)

        except Exception as error:
            raise SystemExit(Exception("Error - {} Unhandled Exception".format(error)))

    def randomkey(self, length=100):
        """
        :param length: max length for the key to be generated
        :return: generate key
        """

        return ''.join(random.sample((string.digits + string.ascii_letters) * 2, length))

