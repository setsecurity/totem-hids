import threading
import configparser
import json
from interfaces import *
from logger import *
from scapy.all import *
from gui.message import *

class Ipv6_protection_init(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.interfaces = Interfaces()
        self.interfaces.update()
        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

    def run(self):

        ip4 = self.interfaces.iface_data['ip4']
        splited_ip4 = ip4.split('.')
        ip4_off = False

        if ip4 == '':ip4_off = True
        elif splited_ip4[0] == '169' and splited_ip4[1] == '254': ip4_off = True

        ipv6 = self.interfaces.iface_data['ip6']

        if ipv6 != '' and ip4_off:
            log = Logger().write('IPv6 attack, ipv6 address is set up and ipv4 addres set down')
            Message().show(log)
            self.save_evidences(log)

        elif ipv6 != '':
            log = Logger().write('IPv6 setup, ipv6 address is set up '+ipv6)
            Message().show(log)
            self.save_evidences(log)



    def save_evidences(self,log):
        if self.config.get('IPV6 protection init', 'save_evidences') == 'True':
            log = log.split('->')[0]

            with open('data/evidences/' + log + '.ifconfig', 'w+') as f:
                f.write('ifconfig \n')
                json.dump(self.interfaces.iface_data, f)
                f.write('\n\ndefault gateway ipv4')
                json.dump(self.interfaces.default_ip4_gateway, f)
                f.write('\ndefault gateway ipv6')
                json.dump(self.interfaces.default_ip6_gateway, f)