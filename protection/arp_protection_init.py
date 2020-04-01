import threading
import configparser
from scapy.all import *
from arptable import *
from interface import *
from protection.arp_protection import *

class ArpProtectionInit(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.config = configparser.ConfigParser()
        self.config.read('totem-hids.config')
        self.arptable = Arptable()
        self.interface = Interface()
        self.interface.update()

    def run(self):
        self.arptable.update()
        duplicated_mac = ArpProtection.check_duplicated_mac()
        if duplicated_mac:
            input = json.dumps(duplicated_mac)
            log = Logger().write('ARP spoof, duplicated mac ' + input + ' detection method check duplicated MAC at init')
            if self.config.get('ARP protection', 'save_evidences') == 'True':
                log = log.split('->')[0]
                log = log.replace(" ", "~") + "ARP-Spoof"
                file = 'data/evidences/' + log + '.pcap'
                with open('data/evidences/' + log + '.arptable', 'w+') as f:
                    f.write('\nsnapshoot arptable ')
                    json.dump(self.arptable.ip_mac, f)
            snapshoot_ip_mac = {key: val for key, val in self.arptable.ip_mac.items()}
            for key, values in duplicated_mac.items():
                if values[0] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[0]])
                if values[1] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[1]])
            for key in snapshoot_ip_mac:
                request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=key, hwdst='ff:ff:ff:ff:ff:ff')
                response = srp1(request, timeout=2, iface=self.interface.iface_name, verbose=0)
            return
        for key, value in self.arptable.ip_mac.items():
            request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=key, hwdst='ff:ff:ff:ff:ff:ff')
            response = srp1(request, timeout=2, iface=self.interface.iface_name, verbose=0)