import threading
import configparser
import json
from datetime import *
import time
from arptable import *
from scapy.all import *
from interfaces import *
from logger import *
from gui.message import *



class Arp_protection(threading.Thread):

    def __init__(self, pkt, ip_mac, arp_spam_record):
        threading.Thread.__init__(self)
        self.pkt = pkt
        self.ip_mac = ip_mac
        self.arp_spam_record = arp_spam_record

        self.mac_src = self.pkt[ARP].hwsrc
        self.ip_src = self.pkt[ARP].psrc
        self.mac_dst = self.pkt[ARP].hwdst
        self.ip_dst = self.pkt[ARP].pdst
        self.op = self.pkt[ARP].op

        self.interfaces = Interfaces()
        self.interfaces.update()
        self.myip = self.interfaces.iface_data['ip4']

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

    def run(self):

        if self.ip_src != self.myip:

            if self.ip_src in self.ip_mac:

                mac_entry = self.ip_mac[self.ip_src]

                if mac_entry == '00:00:00:00:00:00' or self.mac_src == '00:00:00:00:00:00':
                    if (mac_entry == '00:00:00:00:00:00'):
                        interface = self.interfaces.ifaces[self.interfaces.selected_index]
                        request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.ip_src, hwdst='ff:ff:ff:ff:ff:ff')
                        response = srp1(request, timeout=2, iface=interface, verbose=0)
                    return


                self.check_transition()
            else:
                if self.ip_src in Arptable().ip_mac:
                    duplicated_mac = {}
                    for key, value in Arptable().ip_mac.items():
                        if value == self.mac_src:
                            duplicated_mac[key] = value

                    if len(duplicated_mac) > 1:
                        input = json.dumps(duplicated_mac)
                        log = Logger().write('ARP poisoning, duplicated mac ' + input)
                        Message().show(log)

                        if self.config.get('ARP protection','save_evidences') == 'True':
                            self.save_evidences(log)

                        return

                    interface = self.interfaces.ifaces[self.interfaces.selected_index]
                    request = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=self.ip_src, hwdst='ff:ff:ff:ff:ff:ff')
                    response = srp1(request, timeout=2, iface=interface, verbose=0)
                else:
                    self.check_spam()

    def check_transition(self):
        mac_entry = self.ip_mac[self.ip_src]

        if mac_entry != self.mac_src:
            log = Logger().write('ARP poisoning, ' + self.ip_src + ' - ' + mac_entry + ' - ' + self.mac_src)
            Message().show(log)

            if self.config.get('ARP protection','save_evidences') == 'True':
                self.save_evidences(log)

    def check_spam(self):
        arp_spam_dicc = self.arp_spam_record.get()

        ts = time.time()
        time_stamp_now = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        if self.mac_src in arp_spam_dicc:
            time_stamp = arp_spam_dicc[self.mac_src][0]
            count = arp_spam_dicc[self.mac_src][1]
            count = count + 1

            fmt = '%Y-%m-%d %H:%M:%S'
            d1 = datetime.strptime(time_stamp_now, fmt)
            d2 = datetime.strptime(time_stamp, fmt)

            sec_difference = (d1 - d2).total_seconds()

            if sec_difference >= int(self.config.get('ARP protection','check_arp_spam_each')):
                if count >= int(self.config.get('ARP protection','check_arp_spam_max_packets')):
                    log = Logger().write('ARP spam, ' +self.mac_src + ' is unsuccesfully trying ARP poisoning ' + str(count) + ' packets in '+ str(sec_difference) +' seconds')
                    Message().show(log)
                    arp_spam_dicc.clear()

                    if self.config.get('ARP protection','save_evidences') == 'True':
                        log = log.split('->')[0]
                        file = 'data/evidences/' + log + '.pcap'
                        wrpcap(file, self.pkt)
                else:
                    arp_spam_dicc.pop(self.mac_src,None)
            else:
                arp_spam_dicc[self.mac_src][1] = count
        else:
            arp_spam_dicc[self.mac_src] = [time_stamp_now,1]

        self.arp_spam_record.put(arp_spam_dicc)



    def save_evidences(self, log):
        log = log.split('->')[0]
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

    @staticmethod
    def close(sniffer):
        arp_spam_dicc = sniffer.arp_spam_record.get()
        arp_spam_dicc = {}
        sniffer.arp_spam_record.put(arp_spam_dicc)