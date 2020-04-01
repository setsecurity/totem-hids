from logger import *
from protection.arp_protection_init import *
from protection.sniffer import *
from protection.dhcp_protection import *
from interfaces import *
from protection.ipv6_protection_init import *
from protection.ipv6_ndp_protection_init import *
from protection.arp_protection import *
from protection.ipv6_ndp_protection import  *



class Protection(object):

    _instance = None

    def __new__(self):
        if not self._instance:
            self._instance = super(Protection, self).__new__(self)

        return self._instance


    def start(self):
        print('protection start')

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        self.sniffer = Sniffer()
        self.sniffer.start()

        if self.config['ARP protection']['check_arptable_on_start'] == 'True':
            Arp_protection_init().start()

        if self.config['NDP protection']['check_ndptable_on_start'] == 'True':
            Ipv6_ndp_protection_init(self.sniffer.ndp_spoof_record).start()

        if self.config['IPV6 protection init']['active'] == 'True':
            Ipv6_protection_init().start()

    def stop(self):
        print('protection stop')
        self.sniffer.stop = True

        Arp_protection.close(self.sniffer)
        Dhcp_protection.close(self.sniffer)
        Llmnr_protection.close(self.sniffer)
        Ipv6_ndp_protection.close(self.sniffer)
