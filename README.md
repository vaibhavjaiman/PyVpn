# PyVpn

PyVpn project created using Python3.8 targetting users to reduce the load on the paloalto configured vpn gateway or endpoint for users where organization's routes all the traffic from the vpn gateway with best interest in mind for secure browsing however this indeed make things slower slower and slower !!!!!

Do **NOT** use this if your PC is not protected with latest antivirus / Operating System Patches in which case this may lead to significant impact due to malwares/Spywares/Virus.

## Table of Contents

- [Installation](#Installation)
- [Prerequisites](#Prerequisites)
- [Author](#contributing)
- [Release History](#ReleaseHistory)
- [Contact](#Contact)
- [License](#license)

## Installation

These instructions will help you get a copy of the project and use it for your own personal use

``` pip3 install PyVpn```

Post module installation create configuration file `.pyvpn.yaml` in your home directory, Refer [pycpn.yaml.sample](https://github.com/vaibhavjaiman/PyVpn/tree/master/docs)

### Prerequisites

#### Python Module Dependencies
   * [pyyaml](https://github.com/yaml/pyyaml)
   * [pexpect](https://pexpect.readthedocs.io)
   * [netifaces](https://github.com/al45tair/netifaces)

#### Other Dependencies
   * [openconnect](https://formulae.brew.sh/formula/openconnect)
   * [Python 3.8](https://www.python.org/downloads/release/python-381/)

#### Example 1
   * For connecting to the vpn gateway, Default to Palo Alto Gateway

```Python3

from PyVpn import PyVpn
vpn = PyVpn(debug=False)
vpn.start
```
#### Example 2
   * For disconnecting from the Palo Alto vpn gateway

```Python3

from PyVpn import PyVpn
vpn = PyVpn()
vpn.stop
```  
#### Example 3

   * For Generating encrypted password, Lets consider we are using unique key "U3CBrfcJqPLYbXHf2h5B5xmyx0px1a" as per the sample <PyVpn.yaml> config file
   
```Python3

from PyVpn.source.crypt import Crypt
crypt = Crypt()
print(crypt.password.encrypt(password="Sample@123", key="U3CBrfcJqPLYbXHf2h5B5xmyx0px1a"))

```

#### Example 4

   * For Generating random encryption/decryption key
   
```Python3

from PyVpn.source.crypt import Crypt
crypt = Crypt()
print(crypt.randomkey())

```
   
## Author

* **Vaibhav Jaiman** - (https://github.com/vaibhavjaiman)

## ReleaseHistory

* 1.1
  * ADD: Moved to package based
  * ADD: support for encrypted password
  * ADD: `Setup.py` has been added
  
* 1.0
  * ADD: Added palo alto support for MAC users

## Contact
#### System Architect

Reach out to me at one of the following places!

* e-mail: vaibhavjaiman@gmail.com
* linkedin: [@vaibhavjaiman](https://www.linkedin.com/in/vaibhavjaiman/)

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE.md] file for details
