import threading
from scapy.all import *
from datetime import *
import time
import configparser
from interfaces import *
from logger import *
from gui.message import *

class Llmnr_protection(threading.Thread):

    llmnr_pkts_cache = 'data/cache/llmnr_pkts/'

    def __init__(self,pkt,llmnr_ip4_record, llmnr_ip6_record,llmnr_spoofed,llmnr_lock,wpad_spoofed,ndp_spoof_record):
        threading.Thread.__init__(self)
        self.pkt = pkt

        self.llmnr_ip6_record = llmnr_ip6_record
        self.llmnr_ip4_record = llmnr_ip4_record
        self.llmnr_spoofed = llmnr_spoofed
        self.wpad_spoofed = wpad_spoofed
        self.ndp_spoof_record = ndp_spoof_record

        self.llmnr_lock = llmnr_lock

        ts = time.time()
        self.time_stamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        self.sport = self.pkt[UDP].sport
        self.dport = self.pkt[UDP].dport

        interfaces = Interfaces()
        interfaces.update()
        self.myip4 = interfaces.iface_data['ip4']
        self.myip6 = interfaces.iface_data['ip6_link_local']

    def run(self):

        if IP in self.pkt:
            if self.dport == 5355:
                self.llmnr_ip4_query()
            elif self.sport == 5355:
                self.llmnr_ip4_response()

        elif IPv6 in self.pkt:
            if self.dport == 5355:
                self.llmnr_ip6_query()
            elif self.sport == 5355:
                self.llmnr_ip6_response()



    def llmnr_ip4_query(self):
        if self.pkt[IP].src == self.myip4:
            question = str(self.pkt[LLMNRQuery][DNSQR].qname)
            question = question.split('\'')[1].replace('.','').lower()

            llmnr_ip4_dicc = self.llmnr_ip4_record.get()

            if question not in llmnr_ip4_dicc:
                llmnr_ip4_dicc[question] = None
                self.save_pkt(self.llmnr_pkts_cache+question+'_ip4_query.pcap')

            self.llmnr_ip4_record.put(llmnr_ip4_dicc)

    def llmnr_ip4_response(self):
        if self.pkt[IP].src != self.myip4:
            response = str(self.pkt[LLMNRQuery][DNSRR].rdata)

            question = str(self.pkt[LLMNRQuery][DNSQR].qname)
            question = question.split('\'')[1].replace('.', '').lower()

            llmnr_ip4_dicc = self.llmnr_ip4_record.get()

            if question in llmnr_ip4_dicc:
                if llmnr_ip4_dicc[question] == None:
                    llmnr_ip4_dicc[question] = response
                    self.save_pkt(self.llmnr_pkts_cache+question+'_ip4_response.pcap')
                else:
                    if llmnr_ip4_dicc[question] != response:
                        llmnr_spoofed = self.llmnr_spoofed.get()

                        str1 = 'ip4_'+question+'_'+llmnr_ip4_dicc[question]+'_'+response
                        str2 = 'ip4_'+question+'_'+response+'_'+llmnr_ip4_dicc[question]

                        doit = True
                        if str1 in llmnr_spoofed: doit = False
                        elif str2 in llmnr_spoofed: doit = False

                        if doit:
                            log = Logger().write('LLMNR ipv4 spoof, '+question+' - '+llmnr_ip4_dicc[question]+' and '+response)
                            Message().show(log)

                            llmnr_spoofed.append(str1)
                            pkt_query = self.load_pkt(self.llmnr_pkts_cache +question+'_ip4_query.pcap')[0]
                            pkt_response = self.load_pkt(self.llmnr_pkts_cache +question+ '_ip4_response.pcap')[0]

                            if self.config.get('LLMNR protection', 'save_evidences') == 'True':
                                log = log.split('->')[0]
                                pkts = [pkt_query, pkt_response, self.pkt]
                                file = 'data/evidences/' + log + '.pcap'
                                wrpcap(file, pkts)

                        self.llmnr_spoofed.put(llmnr_spoofed)

                if question == 'wpad' and self.config.get('WPAD protection','active') == 'True': self.wpad_protection()

            else:
                print('response withouth query')

            self.llmnr_ip4_record.put(llmnr_ip4_dicc)


    def wpad_protection(self):
        print('entraa')
        response = str(self.pkt[LLMNRQuery][DNSRR].rdata)

        question = str(self.pkt[LLMNRQuery][DNSQR].qname)
        question = question.split('\'')[1].replace('.', '').lower()

        wpad_spoofed = self.wpad_spoofed.get()



        if IP in self.pkt:
            str1 = 'ip4_'+question+'_'+response
            doit = True
            if str1 in wpad_spoofed: doit = False

            if doit:
                log = Logger().write('LLMNR WPAD response, ipv4 response ' + question + ' - ' + response)
                Message().show(log)

                wpad_spoofed.append(str1)
                pkt_query = self.load_pkt(self.llmnr_pkts_cache + question + '_ip4_query.pcap')[0]
                log = log.split('->')[0]
                pkts = [pkt_query, self.pkt]
                file = 'data/evidences/' + log + '.pcap'
                wrpcap(file, pkts)


        elif IPv6 in self.pkt:
            str1 = 'ip6_' + question + '_' + response
            doit = True
            if str1 in wpad_spoofed: doit = False

            if doit:
                log = Logger().write('LLMNR WPAD response, ipv6 response ' + question + ' - ' + response)
                Message().show(log)

                wpad_spoofed.append(str1)
                pkt_query = self.load_pkt(self.llmnr_pkts_cache + question + '_ip6_query.pcap')[0]
                log = log.split('->')[0]
                pkts = [pkt_query, self.pkt]
                file = 'data/evidences/' + log + '.pcap'
                wrpcap(file, pkts)

        self.wpad_spoofed.put(wpad_spoofed)


    def llmnr_ip6_query(self):
        if self.pkt[IPv6].src == self.myip6:
            question = str(self.pkt[LLMNRQuery][DNSQR].qname)
            question = question.split('\'')[1].replace('.','').lower()

            llmnr_ip6_dicc = self.llmnr_ip6_record.get()

            if question not in llmnr_ip6_dicc:
                llmnr_ip6_dicc[question] = None
                self.save_pkt(self.llmnr_pkts_cache+question+'_ip6_query.pcap')

            self.llmnr_ip6_record.put(llmnr_ip6_dicc)

    def llmnr_ip6_response(self):
        if self.pkt[IPv6].src != self.myip6:
            response = str(self.pkt[LLMNRQuery][DNSRR].rdata)

            question = str(self.pkt[LLMNRQuery][DNSQR].qname)
            question = question.split('\'')[1].replace('.', '').lower()

            llmnr_ip6_dicc = self.llmnr_ip6_record.get()

            if question in llmnr_ip6_dicc:
                if llmnr_ip6_dicc[question] == None:
                    llmnr_ip6_dicc[question] = response
                    self.save_pkt(self.llmnr_pkts_cache+question+'_ip6_response.pcap')

                    ndp_spoof_dicc = self.ndp_spoof_record.get()
                    if response in ndp_spoof_dicc:
                        log = Logger().write('The ipv6 of LLMNR query is spoofed, ' + question + ' - ' + llmnr_ip6_dicc[question] + ' and ' + response)
                        Message().show(log)
                    self.ndp_spoof_record.put(ndp_spoof_dicc)

                else:
                    if llmnr_ip6_dicc[question] != response:
                        llmnr_spoofed = self.llmnr_spoofed.get()

                        str1 = 'ip6_'+question+'_'+llmnr_ip6_dicc[question]+'_'+response
                        str2 = 'ip6_'+question+'_'+response+'_'+llmnr_ip6_dicc[question]

                        doit = True
                        if str1 in llmnr_spoofed: doit = False
                        elif str2 in llmnr_spoofed: doit = False

                        if doit:
                            log = Logger().write('LLMNR ipv6 spoof, '+question+' - '+llmnr_ip6_dicc[question]+' and '+response)
                            Message().show(log)

                            llmnr_spoofed.append(str1)
                            pkt_query = self.load_pkt(self.llmnr_pkts_cache +question+'_ip6_query.pcap')[0]
                            pkt_response = self.load_pkt(self.llmnr_pkts_cache +question+ '_ip6_response.pcap')[0]

                            if self.config.get('LLMNR protection', 'save_evidences') == 'True':
                                log = log.split('->')[0]
                                pkts = [pkt_query, pkt_response, self.pkt]
                                file = 'data/evidences/' + log + '.pcap'
                                wrpcap(file, pkts)

                        self.llmnr_spoofed.put(llmnr_spoofed)

                if question == 'wpad' and self.config.get('WPAD protection','active') == 'True': self.wpad_protection()

            else:
                print('response withouth query')

            self.llmnr_ip6_record.put(llmnr_ip6_dicc)



    def save_pkt(self, file):
        self.llmnr_lock.acquire()
        try:
            wrpcap(file, self.pkt)
        finally:
            self.llmnr_lock.release()

    def load_pkt(self, file):
        self.llmnr_lock.acquire()
        pkt = None
        try:
            pkt = rdpcap(file)
        finally:
            self.llmnr_lock.release()
        return pkt

    def remove_pkt(self, file):
        self.llmnr_lock.acquire()
        try:
            os.remove(file)
        finally:
            self.llmnr_lock.release()

    @staticmethod
    def close(sniffer):
        llmnr_ip4_dicc = sniffer.llmnr_ip4_record.get()
        llmnr_ip4_dicc = {}
        sniffer.llmnr_ip4_record.put(llmnr_ip4_dicc)

        llmnr_ip6_dicc = sniffer.llmnr_ip6_record.get()
        llmnr_ip6_dicc = {}
        sniffer.llmnr_ip6_record.put(llmnr_ip6_dicc)

        llmnr_spoofed = sniffer.llmnr_spoofed.get()
        llmnr_spoofed = {}
        sniffer.llmnr_spoofed.put(llmnr_spoofed)

        wpad_spoofed = sniffer.wpad_spoofed.get()
        wpad_spoofed = {}
        sniffer.wpad_spoofed.put(wpad_spoofed)

        sniffer.llmnr_lock.acquire()
        try:
            for the_file in os.listdir('data/cache/llmnr_pkts/'):
                file_path = os.path.join('data/cache/llmnr_pkts/', the_file)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(e)
        finally:
            sniffer.llmnr_lock.release()