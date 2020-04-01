import threading
import configparser
from protection.reminder import *
from scapy.all import *
from interface import *
from arptable import *
from logger import *
import json
from datetime import *
from interface import *


class ArpProtection(threading.Thread):

    def __init__(self, pkt, ip_mac):
        threading.Thread.__init__(self)

        self.config = configparser.ConfigParser()
        self.config.read('totem-hids.config')

        self.pkt = pkt

        self.ip_mac = ip_mac

        self.reminder = Reminder()
        self.arp_spam_record = self.reminder.arp_spam_record

        self.mac_src = self.pkt[ARP].hwsrc
        self.ip_src = self.pkt[ARP].psrc
        self.mac_dst = self.pkt[ARP].hwdst
        self.ip_dst = self.pkt[ARP].pdst
        self.op = self.pkt[ARP].op

        self.interface = Interface()
        self.interface.update()
        self.myip = self.interface.iface_data['ip4']

    def run(self):
        if self.ip_src != self.myip:
            #print(self.getName() + " IP.SRC " + self.ip_src + " MAC.SRC " + self.mac_src)
            if self.ip_src in self.ip_mac:
                self.ipsrc_in_arpentry()
            else:
                self.ipsrc_notin_arpentry()

    def ipsrc_in_arpentry(self):
        mac_entry = self.ip_mac[self.ip_src]
        if mac_entry == '00:00:00:00:00:00' or self.mac_src == '00:00:00:00:00:00':
            if (mac_entry == '00:00:00:00:00:00'):
                request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.ip_src, hwdst='ff:ff:ff:ff:ff:ff')
                response = srp1(request, timeout=2, iface=self.interface.iface_name, verbose=0)
            return

        self.check_transition()

    def ipsrc_notin_arpentry(self):
        if self.mac_src == '00:00:00:00:00:00':
            return
        duplicated_mac = {}
        duplicated_mac[self.ip_src] = self.mac_src
        for key, value in self.ip_mac.items():
            if value == self.mac_src:
                duplicated_mac[key] = value
        if len(duplicated_mac) > 1:
            log = ''
            if self.ip_src in Arptable().ip_mac:
                print('ARP spoofing, ' + str(duplicated_mac) + 'detection method duplicated MAC, packet learned')
                log = Logger().write('ARP spoofing, ' + str(duplicated_mac) + 'detection method duplicated MAC, packet learned')
            else:
                print('ARP spoofing, ' + str(duplicated_mac) + 'detection method duplicated MAC, packet not learned')
                log = Logger().write('ARP spoofing, ' + str(duplicated_mac) + 'detection method duplicated MAC, packet not learned')
            if self.config.get('ARP protection', 'save_evidences') == 'True':
                self.save_evidences(log)
        else:
            if self.ip_src in Arptable().ip_mac:
                interface = self.interface.iface_name
                request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.ip_src, hwdst='ff:ff:ff:ff:ff:ff')
                response = srp1(request, timeout=2, iface=interface, verbose=0)
            else:
                self.check_spam()

    def check_transition(self):
        mac_entry = self.ip_mac[self.ip_src]
        if mac_entry != self.mac_src:
            print('ARP spoofing, ' + self.ip_src + ' - ' + mac_entry + ' - ' + self.mac_src + ' detection method Check Transition')
            log = Logger().write('ARP spoofing, ' + self.ip_src + ' - ' + mac_entry + ' - ' + self.mac_src + ' detection method Check Transition')
            if self.config.get('ARP protection', 'save_evidences') == 'True':
                self.save_evidences(log)

    def check_spam(self):
        arp_spam_dicc = self.arp_spam_record.get()
        ts = datetime.now()
        time_stamp_now = ts.strftime('%Y-%m-%d %H:%M:%S')
        if self.mac_src in arp_spam_dicc:
            time_stamp = arp_spam_dicc[self.mac_src][0]
            count = arp_spam_dicc[self.mac_src][1]
            count = count + 1
            fmt = '%Y-%m-%d %H:%M:%S'
            d1 = datetime.strptime(time_stamp_now, fmt)
            d2 = datetime.strptime(time_stamp, fmt)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference >= int(self.config.get('ARP protection', 'check_arp_spam_each')):
                if count >= int(self.config.get('ARP protection', 'check_arp_spam_max_packets')):
                    log = Logger().write('ARP spam, ' + self.mac_src + str(count) + ' packets in ' + str(sec_difference) + ' seconds')
                    arp_spam_dicc.pop(self.mac_src, None)
                    if self.config.get('ARP protection', 'save_evidences') == 'True':
                        log = log.split('->')[0]
                        log = log.replace(" ", "~") + "ARP-Spam"
                        file = 'data/evidences/' + log + '.pcap'
                        wrpcap(file, self.pkt)
                else:
                    arp_spam_dicc.pop(self.mac_src, None)
            else:
                arp_spam_dicc[self.mac_src][1] = count
        else:
            arp_spam_dicc[self.mac_src] = [time_stamp_now, 1]
        self.arp_spam_record.put(arp_spam_dicc)

    def save_evidences(self,log):
        log = log.split('->')[0]
        log = log.replace(" ", "~") + "ARP-Spoof"
        file = 'data/evidences/' + log + '.pcap'
        wrpcap(file, self.pkt)
        with open('data/evidences/' + log + '.arptable', 'w+') as f:
            f.write('snapshoot arptable 1 ')
            json.dump(self.ip_mac, f)
            f.write('\nsnapshoot arptable 2 ')
            json.dump(Arptable().ip_mac, f)

    @staticmethod
    def check_duplicated_mac():
        arptable = Arptable()
        rev_ip_mac = {}
        for key, value in arptable.ip_mac.items():
            rev_ip_mac.setdefault(value, set()).add(key)
        duplicated_entrys = {}
        for key, values in rev_ip_mac.items():
            if (len(values) > 1):
                ar = []
                for keys in values:
                    ar.append(keys)
                duplicated_entrys[key] = ar
        return duplicated_entrys
