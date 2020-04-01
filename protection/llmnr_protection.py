import threading
from scapy.all import *
from datetime import *
import configparser
from interface import *
from logger import *
from protection.reminder import *
import re

class Llmnr_protection(threading.Thread):

    time_format = '%Y-%m-%d %H:%M:%S'

    def __init__(self, pkt):
        threading.Thread.__init__(self)
        self.pkt = pkt
        ts = datetime.now()
        self.time_stamp = ts.strftime(self.time_format)
        self.sport = self.pkt[UDP].sport
        self.dport = self.pkt[UDP].dport
        self.config = configparser.ConfigParser()
        self.config.read('totem-hids.config')
        self.reminder = Reminder()
        self.llmnr_ip4_record = self.reminder.llmr_ip4_record
        self.llmnr_ip6_record = self.reminder.llmr_ip6_record
        interface = Interface()
        interface.update()
        self.myip4 = interface.iface_data['ip4']
        self.myip6 = interface.iface_data['ip6_link_local']

    def run(self):
        if IP in self.pkt:
            # si es query
            if self.dport == 5355:
                self.llmnr_ip4_query()
            # si es response
            elif self.sport == 5355:
                self.llmnr_ip4_response()

    def llmnr_ip4_query(self):
        question = str(self.pkt[LLMNRQuery][DNSQR].qname)
        question = question.split('\'')[1].replace('.', '').lower()
        llmnr_ip4_dicc = self.llmnr_ip4_record.get()
        if question not in llmnr_ip4_dicc:
            llmnr_ip4_dicc[question] = [self.time_stamp, self.pkt, None]
        self.llmnr_ip4_record.put(llmnr_ip4_dicc)
        self.clear_llmnr_ip4_record()

    def llmnr_ip4_response(self):
        if self.pkt[IP].src != self.myip4:
            response = str(self.pkt[LLMNRResponse][DNSRR].rdata)
            question = str(self.pkt[LLMNRResponse][DNSQR].qname)
            question = question.split('\'')[1].replace('.', '').lower()
            llmnr_ip4_dicc = self.llmnr_ip4_record.get()
            if question in llmnr_ip4_dicc:
                if llmnr_ip4_dicc[question][2] == None:
                    llmnr_ip4_dicc[question][2] = self.pkt
                else:
                    pkt_response = llmnr_ip4_dicc[question][2]
                    response2 = str(pkt_response[LLMNRResponse][DNSRR].rdata)
                    if response != response2:
                        print('LLMNR spoofing IPv4, query '+question+' response '+response+' '+response2)
                        log = Logger().write('LLMNR spoofing IPv4, query '+question+' response '+response+' '+response2)
                        if self.config.get('LLMNR protection', 'save_evidences') == 'True':
                            self.save_evidences(log, llmnr_ip4_dicc[question][1], llmnr_ip4_dicc[question][2])
            else:
                print('response withouth query')
            self.llmnr_ip4_record.put(llmnr_ip4_dicc)
            self.clear_llmnr_ip4_record()
            if question == 'wpad' or question == 'WPAD':
                self.wpad4_check()

    def clear_llmnr_ip4_record(self):
        llmnr_ip4_dicc = self.llmnr_ip4_record.get()
        llmnr_del_keys = []
        for key, value in llmnr_ip4_dicc.items():
            d1 = datetime.strptime(self.time_stamp, self.time_format)
            pkt_timestamp = value[0]
            d2 = datetime.strptime(pkt_timestamp, self.time_format)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('LLMNR protection', 'packets_max_age')):
                llmnr_del_keys.append(key)
        for key in llmnr_del_keys:
            llmnr_ip4_dicc.pop(key, None)
        self.llmnr_ip4_record.put(llmnr_ip4_dicc)

    def llmnr_ip6_query(self):
        question = str(self.pkt[LLMNRQuery][DNSQR].qname)
        question = question.split('\'')[1].replace('.', '').lower()
        llmnr_ip6_dicc = self.llmnr_ip6_record.get()
        if question not in llmnr_ip6_dicc:
            llmnr_ip6_dicc[question] = [self.time_stamp, self.pkt, None]
        self.llmnr_ip6_record.put(llmnr_ip6_dicc)
        self.clear_llmnr_ip6_record()

    def llmnr_ip6_response(self):
        if self.pkt[IPv6].src == self.myip6:
            response = str(self.pkt[LLMNRResponse][DNSRR].rdata)
            question = str(self.pkt[LLMNRResponse][DNSQR].qname)
            question = question.split('\'')[1].replace('.', '').lower()
            llmnr_ip6_dicc = self.llmnr_ip6_record.get()
            if question in llmnr_ip6_dicc:
                if llmnr_ip6_dicc[question][2] == None:
                    llmnr_ip6_dicc[question][2] = self.pkt
                else:
                    pkt_response = llmnr_ip6_dicc[question][2]
                    response2 = str(pkt_response[LLMNRResponse][DNSRR].rdata)
                    print(response2)
                    if response != response2:
                        print('LLMNR spoofing IPv6, query '+question+' response '+response+' '+response2)
                        log = Logger().write('LLMNR spoofing IPv6, query '+question+' response '+response+' '+response2)
                        if self.config.get('LLMNR protection', 'save_evidences') == 'True':
                            self.save_evidences(log, llmnr_ip6_dicc[question][1], llmnr_ip6_dicc[question][2])
            else:
                print('response withouth query')
            self.llmnr_ip6_record.put(llmnr_ip6_dicc)
            self.clear_llmnr_ip6_record()
            if question == 'wpad' or question == 'WPAD':
                self.wpad6_check()

    def clear_llmnr_ip6_record(self):
        llmnr_ip6_dicc = self.llmnr_ip6_record.get()
        llmnr_del_keys = []
        for key, value in llmnr_ip6_dicc.items():
            d1 = datetime.strptime(self.time_stamp, self.time_format)
            pkt_timestamp = value[0]
            d2 = datetime.strptime(pkt_timestamp, self.time_format)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('LLMNR protection', 'packets_max_age')):
                llmnr_del_keys.append(key)
        for key in llmnr_del_keys:
            llmnr_ip6_dicc.pop(key, None)
        self.llmnr_ip6_record.put(llmnr_ip6_dicc)

    def wpad4_check(self):
        response = str(self.pkt[LLMNRResponse][DNSRR].rdata)
        question = str(self.pkt[LLMNRResponse][DNSQR].qname)
        question = question.split('\'')[1].replace('.', '').lower()
        ip_regex = re.compile('((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-4]|2[0-5][0-9]|[01]?[0-9][0-9]?))')
        if re.findall(ip_regex, response):
            print('LLMNR spoofing IPv4 WPAD response from private network')
            log = Logger().write('LLMNR spoofing IPv4 WPAD response from private network')
            if self.config.get('LLMNR protection', 'save_evidences') == 'True':
                log = log.split('->')[0]
                log = log.replace(" ", "~") + "LLMNR-WPAD-IPv4-Spoof"
                file = 'data/evidences/' + log + '.pcap'
                wrpcap(file, self.pkt)

    def wpad6_check(self):
        print('LLMNR spoofing IPv6 WPAD response from private network')
        log = Logger().write('LLMNR spoofing IPv6 WPAD')
        if self.config.get('LLMNR protection', 'save_evidences') == 'True':
            log = log.split('->')[0]
            log = log.replace(" ", "~") + "LLMNR-WPAD-IPv46Spoof"
            file = 'data/evidences/' + log + '.pcap'
            wrpcap(file, self.pkt)

    def save_evidences(self, log, pkt_query, pkt_response):
        log = log.split('->')[0]
        log = log.replace(" ", "~") + "LLMNR-Spoof"
        pkts = [pkt_query, pkt_response, self.pkt]
        file = 'data/evidences/' + log + '.pcap'
        wrpcap(file, pkts)
