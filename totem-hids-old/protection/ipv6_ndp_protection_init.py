import threading
import configparser
from scapy.all import *
from interfaces import *
from ndptable import *
from protection.ipv6_ndp_protection import *
from gui.message import *

class Ipv6_ndp_protection_init(threading.Thread):

    def __init__(self,ndp_spoof_record):
        threading.Thread.__init__(self)

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        self.ndp_spoof_record = ndp_spoof_record

        self.ndptable = Ndptable()
        self.interfaces = Interfaces()
        self.interfaces.update()
        self.interface = self.interfaces.ifaces[self.interfaces.selected_index]
        self.myip = self.interfaces.iface_data['ip6_link_local']
        self.mymac = self.interfaces.iface_data['mac']

    def run(self):
        self.ndptable.update()

        duplicated_mac = Ipv6_ndp_protection.check_duplicated_mac()

        if duplicated_mac:
            input = json.dumps(duplicated_mac)
            log = Logger().write('NDP poisoning, duplicated mac ' + input)
            Message().show(log)

            for key,value in duplicated_mac.items():
                ndp_spoof_dicc = self.ndp_spoof_record.get()
                ndp_spoof_dicc[value[0]] = [key]
                ndp_spoof_dicc[value[1]] = [key]
                self.ndp_spoof_record.put(ndp_spoof_dicc)

            if self.config.get('NDP protection','save_evidences') == 'True':
                log = log.split('->')[0]
                with open('data/evidences/' + log + '.ndptable', 'w+') as f:
                    f.write('\nsnapshoot ndptable ')
                    json.dump(Ndptable().ip_mac, f)

            snapshoot_ip_mac = {key: val for key, val in self.ndptable.ip_mac.items()}
            for key,values in duplicated_mac.items():
                if values[0] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[0]])
                if values[1] in snapshoot_ip_mac: del (snapshoot_ip_mac[values[1]])

            for key in snapshoot_ip_mac:
                ether = (Ether(dst='ff:ff:ff:ff:ff:ff', src=self.mymac))
                ipv6 = IPv6(src=self.myip, dst=key)
                ns = ICMPv6ND_NS(tgt=key)

                request = ether / ipv6 / ns
                response = srp1(request, timeout=2, iface=self.interface, verbose=0)
            return

        for key, value in self.ndptable.ip_mac.items():
            ether = (Ether(dst='ff:ff:ff:ff:ff:ff', src=self.mymac))
            ipv6 = IPv6(src=self.myip, dst=key)
            ns = ICMPv6ND_NS(tgt=key)
            request = ether / ipv6 / ns
            response = srp1(request, timeout=2, iface=self.interface, verbose=0)