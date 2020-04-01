import threading
import configparser
from interfaces import *
from scapy.all import *
from logger import *
import json
from ndptable import *
from datetime import *
import time
from gui.message import *

class Ipv6_ndp_protection(threading.Thread):

    def __init__(self, pkt,ip_mac,ndp_spam_record,ndp_spoof_record):
        threading.Thread.__init__(self)
        self.pkt = pkt
        self.ip_mac = ip_mac

        self.ndp_spam_record = ndp_spam_record
        self.ndp_spoof_record = ndp_spoof_record

        self.mac_src = self.pkt[Ether].src
        self.ip_src = self.pkt[IPv6].src
        self.mac_dst = self.pkt[Ether].dst
        self.ip_dst = self.pkt[IPv6].dst

        self.tgt = self.ip_src
        self.lladr = self.mac_src

        self.interfaces = Interfaces()
        self.interfaces.update()
        self.myip = self.interfaces.iface_data['ip6_link_local']
        self.mymac = self.interfaces.iface_data['mac']

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

    def run(self):


        if self.ip_src != self.myip:
            if self.tgt in self.ip_mac:
                self.check_transition()
            else:
                if self.tgt in Ndptable().ip_mac:
                    duplicated_mac = {}
                    for key, value in Ndptable().ip_mac.items():
                        if value == self.mac_src:
                            duplicated_mac[key] = value

                            ndp_spoof_dicc = self.ndp_spoof_record.get()
                            ndp_spoof_dicc[self.tgt] = [value, self.lladr]
                            self.ndp_spoof_record.put(ndp_spoof_dicc)

                    if len(duplicated_mac) > 1:
                        input = json.dumps(duplicated_mac)
                        log = Logger().write('NDP poisoning, duplicated mac ' + input)
                        Message().show(log)

                        if self.config.get('NDP protection', 'save_evidences') == 'True':
                            self.save_evidences(log)

                        return

                    interface = self.interfaces.ifaces[self.interfaces.selected_index]

                    ether = (Ether(dst='ff:ff:ff:ff:ff:ff', src=self.mymac))
                    ipv6 = IPv6(src=self.myip, dst=self.ip_src)
                    ns = ICMPv6ND_NS(tgt=self.ip_src)

                    request = ether / ipv6 / ns
                    response = srp1(request, timeout=2, iface=interface, verbose=0)
                else:
                    self.check_spam()




    def check_transition(self):
        mac_entry = self.ip_mac[self.tgt]
        if mac_entry != self.lladr:
            log = Logger().write('NDP poisoning, ' + self.tgt + ' - ' + mac_entry + ' - ' + self.lladr)
            Message().show(log)

            ndp_spoof_dicc = self.ndp_spoof_record.get()
            ndp_spoof_dicc[self.tgt] = [mac_entry,self.lladr]
            self.ndp_spoof_record.put(ndp_spoof_dicc)

            if self.config.get('NDP protection','save_evidences') == 'True':
                self.save_evidences(log)



    def check_spam(self):
        ndp_spam_dicc = self.ndp_spam_record.get()

        ts = time.time()
        time_stamp_now = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        if self.lladr in ndp_spam_dicc:

            time_stamp = ndp_spam_dicc[self.lladr][0]
            count = ndp_spam_dicc[self.lladr][1]
            count = count + 1

            fmt = '%Y-%m-%d %H:%M:%S'
            d1 = datetime.strptime(time_stamp_now, fmt)
            d2 = datetime.strptime(time_stamp, fmt)

            sec_difference = (d1 - d2).total_seconds()

            if sec_difference >= int(self.config.get('NDP protection', 'check_na_spam_each')):

                if count >= int(self.config.get('NDP protection', 'check_na_spam_max_packets')):
                    log = Logger().write('NDP spam, ' + self.mac_src + 'is unsuccesfully trying NDP poisoning ' + str(count) + ' packets in ' + str(sec_difference) + ' seconds')
                    Message().show(log)

                    ndp_spam_dicc.clear()

                    if self.config.get('NDP protection', 'save_evidences') == 'True':
                        log = log.split('->')[0]
                        file = 'data/evidences/' + log + '.pcap'
                        wrpcap(file, self.pkt)
                else:
                    ndp_spam_dicc.pop(self.lladr, None)
            else:
                ndp_spam_dicc[self.lladr][1] = count
        else:
            ndp_spam_dicc[self.lladr] = [time_stamp_now, 1]


        self.ndp_spam_record.put(ndp_spam_dicc)


    def save_evidences(self, log):
        log = log.split('->')[0]
        file = 'data/evidences/' + log + '.pcap'
        wrpcap(file, self.pkt)

        with open('data/evidences/' + log + '.ndptable', 'w+') as f:
            f.write('snapshoot ndptable 1 ')
            json.dump(self.ip_mac, f)
            f.write('\nsnapshoot ndptable 2 ')
            json.dump(Ndptable().ip_mac, f)

    @staticmethod
    def check_duplicated_mac():
        ndptable = Ndptable()
        rev_ip_mac = {}
        for key, value in ndptable.ip_mac.items():
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
        ndp_spam_dicc = sniffer.ndp_spam_record.get()
        ndp_spam_dicc = {}
        sniffer.ndp_spam_record.put(ndp_spam_dicc)

        ndp_spoof_dicc = sniffer.ndp_spoof_record.get()
        ndp_spoof_dicc = {}
        sniffer.ndp_spoof_record.put(ndp_spoof_dicc)