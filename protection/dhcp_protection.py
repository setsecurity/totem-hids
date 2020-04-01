import threading
import configparser
from datetime import *
from interface import *
from scapy.all import *
from logger import *
from protection.reminder import *


class Dhcp_protection(threading.Thread):

    dhcp_types = {
        1: 'discover',
        2: 'offer',
        3: 'request',
        4: 'decline',
        5: 'ack',
        6: 'nak',
        7: 'release',
        8: 'inform',
        9: 'force_renew',
        10: 'lease_query',
        11: 'lease_unassigned',
        12: 'lease_unknown',
        13: 'lease_active'
    }

    time_format = '%Y-%m-%d %H:%M:%S'

    starvation_active = False

    def __init__(self, pkt):
        threading.Thread.__init__(self)
        ts = datetime.now()
        self.time_stamp = ts.strftime(self.time_format)
        self.pkt = pkt
        self.reminder = Reminder()
        self.dhcp_discover_record = self.reminder.dhcp_discover_record
        self.dhcp_offer_record = self.reminder.dhcp_offer_record
        self.dhcp_request_record = self.reminder.dhcp_request_record
        self.dhcp_ack_record = self.reminder.dhcp_ack_record
        self.op = self.pkt[BOOTP].op
        self.xid = str(self.pkt[BOOTP].xid)
        self.type = self.dhcp_types[self.pkt[DHCP].options[0][1]]
        interface = Interface()
        interface.update()
        self.mymac = interface.iface_data['mac']
        self.config = configparser.ConfigParser()
        self.config.read('totem-hids.config')

    def run(self):
        if self.type == 'discover':
            #print(self.getName() + ' DHCP discover ' + self.xid + " " + self.pkt[Ether].src)
            self.dhcp_discover()
        elif self.type == 'offer':
            #print(self.getName() + ' DHCP offer ' + self.xid + " " + self.pkt[Ether].src)
            self.dhcp_offer()
        if self.type == 'request':
            #print(self.getName() + ' DHCP request ' + self.xid + " " + self.pkt[Ether].src)
            self.dhcp_request()
        elif self.type == 'ack':
            #print(self.getName() + ' DHCP ack ' + self.xid + " " + self.pkt[Ether].src)
            self.dhcp_ack()

    def dhcp_discover(self):
        if self.pkt[Ether].src != self.mymac:
            self.clear_record_discoffer()
            return

        dhcp_discover_dicc = self.dhcp_discover_record.get()
        dhcp_discover_dicc[self.xid] = [self.time_stamp, self.pkt]
        self.dhcp_discover_record.put(dhcp_discover_dicc)
        self.clear_record_discoffer()

    def dhcp_offer(self):
        if self.pkt[Ether].src == self.mymac:
            print('DHCP protection: this offer is sended by me, im a dhcp server')
            self.clear_record_discoffer()
            return
        dhcp_offer_dicc = self.dhcp_offer_record.get()
        if self.xid in dhcp_offer_dicc:
            print('DHCP rogue server, more than one dhcp offer with same transaction id ' + self.xid)
            log = Logger().write('DHCP rogue server, more than one dhcp offer with same transaction id ' + self.xid)
            if self.config.get('DHCP protection', 'save_evidences') == 'True':
                self.save_evidences_rogue_server(log, dhcp_offer_dicc[self.xid][1])
        else:
            dhcp_discover_dicc = self.dhcp_discover_record.get()
            if self.xid not in dhcp_discover_dicc:
                print('DHCP protection: dhcp offer without previous discover, transaction id ' + self.xid)
                self.dhcp_discover_record.put(dhcp_discover_dicc)
                return
            self.dhcp_discover_record.put(dhcp_discover_dicc)
            dhcp_offer_dicc[self.xid] = [self.time_stamp, self.pkt]
        self.dhcp_offer_record.put(dhcp_offer_dicc)
        self.clear_record_discoffer()

    def clear_record_discoffer(self):
        dhcp_discover_dicc = self.dhcp_discover_record.get()
        dhcp_offer_dicc = self.dhcp_offer_record.get()
        discover_del_keys = []
        offer_del_keys = []

        for key, value in dhcp_discover_dicc.items():
            d1 = datetime.strptime(self.time_stamp, self.time_format)
            pkt_timestamp = value[0]
            d2 = datetime.strptime(pkt_timestamp, self.time_format)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('DHCP protection', 'packets_max_age')):
                discover_del_keys.append(key)
                if key in dhcp_offer_dicc:
                    offer_del_keys.append(key)
        for key in discover_del_keys:
            dhcp_discover_dicc.pop(key, None)
        for key in offer_del_keys:
            dhcp_offer_dicc.pop(key, None)
        self.dhcp_discover_record.put(dhcp_discover_dicc)
        self.dhcp_offer_record.put(dhcp_offer_dicc)

    def dhcp_request(self):
        if self.pkt[Ether].src != self.mymac:
            print('DHCP protection: this request is not mine maybe im a DHCP server')
            self.clear_record_reqack()
            return
        dhcp_request_dicc = self.dhcp_request_record.get()
        dhcp_request_dicc[self.xid] = [self.time_stamp, self.pkt]
        self.dhcp_request_record.put(dhcp_request_dicc)
        self.clear_record_reqack()

    def dhcp_ack(self):
        if self.pkt[Ether].src == self.mymac:
            print('DHCP protection: this ack is sended by me, im a dhcp server')
            self.clear_record_reqack()
            return
        dhcp_ack_dicc = self.dhcp_ack_record.get()
        if self.xid in dhcp_ack_dicc:
            pkt_ack = dhcp_ack_dicc[self.xid][1]
            print('DHCP ack injection, acks from ' + pkt_ack[Ether].src + ' and ' + self.pkt[Ether].src)
            log = Logger().write('DHCP ack injection, acks from ' + pkt_ack[Ether].src + ' and ' + self.pkt[Ether].src)
            if self.config.get('DHCP protection', 'save_evidences') == 'True':
                self.save_evidences_ack_injection(log, pkt_ack)
        else:
            dhcp_ack_dicc[self.xid] = [self.time_stamp, self.pkt]
        self.dhcp_ack_record.put(dhcp_ack_dicc)
        self.clear_record_reqack()

    def clear_record_reqack(self):
        dhcp_request_dicc = self.dhcp_request_record.get()
        dhcp_ack_dicc = self.dhcp_ack_record.get()
        request_del_keys = []
        ack_del_keys = []
        for key, value in dhcp_request_dicc.items():
            d1 = datetime.strptime(self.time_stamp, self.time_format)
            pkt_timestamp = value[0]
            d2 = datetime.strptime(pkt_timestamp, self.time_format)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('DHCP protection', 'packets_max_age')):
                request_del_keys.append(key)
                if key in dhcp_ack_dicc:
                    ack_del_keys.append(key)
        for key in request_del_keys:
            dhcp_request_dicc.pop(key, None)
        for key in ack_del_keys:
            dhcp_ack_dicc.pop(key, None)
        self.dhcp_request_record.put(dhcp_request_dicc)
        self.dhcp_ack_record.put(dhcp_ack_dicc)

    @staticmethod
    def check_dhcp_starvation(pkt):
        dhcp_dos = Reminder().dhcp_dos_record.get()
        type = Dhcp_protection.dhcp_types[pkt[DHCP].options[0][1]]
        config = configparser.ConfigParser()
        config.read('totem-hids.config')
        time_format = '%Y-%m-%d %H:%M:%S'
        ts = datetime.now()
        time_stamp = ts.strftime(time_format)
        if not dhcp_dos:
            dhcp_dos = [time_stamp, 1]
        else:
            dos_time_stamp = dhcp_dos[0]
            d1 = datetime.strptime(time_stamp, time_format)
            d2 = datetime.strptime(dos_time_stamp, time_format)
            sec_difference = (d1 - d2).total_seconds()
            count = dhcp_dos[1]
            if sec_difference > int(config.get('DHCP protection', 'check_dhcp_dos_each')):
                if count > int(config.get('DHCP protection', 'check_dhcp_dos_max_packets')):
                    print('DHCP Starvation '+type+', ' + str(count) + ' discover in ' + str(config.get('DHCP protection', 'check_dhcp_dos_each')) + ' seconds')
                    log = Logger().write('DHCP Starvation '+type+', ' + str(count) + ' discover in ' + str(config.get('DHCP protection', 'check_dhcp_dos_each')) + ' seconds')
                    Dhcp_protection.starvation_active = True
                else:
                    Dhcp_protection.starvation_active = False
                dhcp_dos = []
            else:
                count = count + 1
                dhcp_dos[1] = count
        Reminder().dhcp_dos_record.put(dhcp_dos)
        return Dhcp_protection.starvation_active

    def save_evidences_rogue_server(self, log, pkt_offer):
        dhcp_discover_dicc = self.dhcp_discover_record.get()
        log = log.split('->')[0]
        log = log.replace(" ", "~") + "DHCP-Rogue-Server"
        pkt_discover = dhcp_discover_dicc[self.xid][1]
        pkts = [pkt_discover, pkt_offer, self.pkt]
        file = 'data/evidences/' + log + '.pcap'
        wrpcap(file, pkts)
        self.dhcp_discover_record.put(dhcp_discover_dicc)

    def save_evidences_ack_injection(self, log, pkt_ack):
        dhcp_request_dicc = self.dhcp_request_record.get()
        log = log.split('->')[0]
        log = log.replace(" ", "~") + "DHCP-ACK-Injection"
        pkt_request = dhcp_request_dicc[self.xid][1]
        pkts = [pkt_request, pkt_ack, self.pkt]
        file = 'data/evidences/' + log + '.pcap'
        wrpcap(file, pkts)
        self.dhcp_request_record.put(dhcp_request_dicc)

