import threading
import configparser
from scapy.all import *
from arptable import *
from interfaces import *
from protection.arp_protection import *
from gui.message import *

class Arp_protection_init(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        self.arptable = Arptable()
        self.interfaces = Interfaces()
        self.interfaces.update()
        self.interface = self.interfaces.ifaces[self.interfaces.selected_index]

    def run(self):
        self.arptable.update()

        duplicated_mac = Arp_protection.check_duplicated_mac()

        if duplicated_mac:
            input = json.dumps(duplicated_mac)
            log = Logger().write('ARP poisoning, duplicated mac ' + input)
            Message().show(log)

            if self.config.get('ARP protection','save_evidences') == 'True':
                log = log.split('->')[0]
                file = 'data/evidences/' + log + '.pcap'

                with open('data/evidences/' + log + '.arptable', 'w+') as f:
                    f.write('\nsnapshoot arptable ')
                    json.dump(Arptable().ip_mac, f)

            snapshoot_ip_mac = {key: val for key, val in self.arptable.ip_mac.items()}
            for key, values in duplicated_mac.items():
                if values[0] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[0]])
                if values[1] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[1]])

            for key in snapshoot_ip_mac:
                request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=key, hwdst='ff:ff:ff:ff:ff:ff')
                response = srp1(request, timeout=2, iface=self.interface, verbose=0)
            return

        for key, value in self.arptable.ip_mac.items():
            request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=key, hwdst='ff:ff:ff:ff:ff:ff')
            response = srp1(request, timeout=2, iface=self.interface, verbose=0)