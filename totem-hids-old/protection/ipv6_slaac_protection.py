import threading
import configparser
import json
from interfaces import *
from logger import *
from scapy.all import *
from protection.ipv6_slaac_updater import *
from gui.message import *

class Ipv6_slaac_protection(threading.Thread):

    def __init__(self,pkt,iface_data_snapshoot,slaac_attack_on):
        threading.Thread.__init__(self)
        self.iface_data_old = iface_data_snapshoot
        self.interfaces = Interfaces()
        self.interfaces.update()
        self.slaac_attack_on = slaac_attack_on

        self.pkt = pkt

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')


    def run(self):

        ip6_old = self.iface_data_old['ip6']
        ip6_new = self.interfaces.iface_data['ip6']
        ip6_netmask = self.interfaces.iface_data['netmask6']


        prefix = self.pkt['ICMPv6 Neighbor Discovery Option - Prefix Information'].prefix
        netmask = str(self.pkt['ICMPv6 Neighbor Discovery Option - Prefix Information'].prefixlen)

        splited_prefix = prefix.split(':')
        splited_prefix = list(filter(None,splited_prefix))
        splited_ip6_new = ip6_new.split(':')
        ip6_netmask = ip6_netmask.split('/')[1]


        ip4 = self.interfaces.iface_data['ip4']
        splited_ip4 = ip4.split('.')
        ip4_off = False

        if ip4 == '': ip4_off = True
        else:
            if splited_ip4[0] == '169' and splited_ip4[1] == '254': ip4_off = True

        if ip6_old == '' and ip6_new != '':

            if ip6_netmask == netmask:
                pefix_equal = True
                pos = 0
                for i in splited_prefix:
                    if i != splited_ip6_new[pos]: pefix_equal = False
                    pos = pos+1

                if pefix_equal:
                    src_mac = self.pkt[Ether].src
                    if ip4_off:
                        log = Logger().write('ICMPv6 SLAAC attack, '+src_mac+' sends RA with prefix '+prefix)
                        Message().show(log)
                        self.save_evidences(log)
                    else:
                        log = Logger().write('ICMPv6 RA set up ipv6 address, '+src_mac+' sends RA with prefix '+prefix)
                        Message().show(log)
                        self.save_evidences(log)

                    slaac_attack = self.slaac_attack_on.get()
                    slaac_attack = True
                    self.slaac_attack_on.put(slaac_attack)

                    Ipv6_slaac_updater(self.slaac_attack_on).start()



    def save_evidences(self,log):
        if self.config.get('SLAAC protection', 'save_evidences') == 'True':
            log = log.split('->')[0]
            file = 'data/evidences/' + log + '.pcap'
            wrpcap(file, self.pkt)

            with open('data/evidences/' + log + '.ifconfig', 'w+') as f:
                f.write('snapshoot ifconfig 1 \n')
                json.dump(self.iface_data_old, f)
                f.write('\nsnapshoot ifconfig 2 \n')
                json.dump(self.interfaces.iface_data, f)
                f.write('\n\ndefault gateway ipv4')
                json.dump(self.interfaces.default_ip4_gateway, f)
                f.write('\ndefault gateway ipv6')
                json.dump(self.interfaces.default_ip6_gateway, f)
