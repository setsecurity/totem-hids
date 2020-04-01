import threading
import configparser
from datetime import *
import time
from scapy.all import *
from interfaces import *
from logger import *
from gui.message import *

class Dhcp_protection(threading.Thread):

    dhcp_pkts_cache = 'data/cache/dhcp_pkts/'

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

    def __init__(self, pkt, dhcp_discover_record, dhcp_offer_record, dhcp_request_record, dhcp_ack_record, dhcp_lock, dhcp_dos_record):
        threading.Thread.__init__(self)
        self.pkt = pkt

        self.dhcp_discover_record = dhcp_discover_record
        self.dhcp_offer_record = dhcp_offer_record
        self.dhcp_request_record = dhcp_request_record
        self.dhcp_ack_record = dhcp_ack_record
        self.dhcp_lock = dhcp_lock
        self.dhcp_dos_record = dhcp_dos_record

        self.op = self.pkt[BOOTP].op
        self.xid = str(self.pkt[BOOTP].xid)

        self.type = self.dhcp_types[self.pkt[DHCP].options[0][1]]

        ts = time.time()
        self.time_stamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

        interfaces = Interfaces()
        interfaces.update()
        self.mymac = interfaces.iface_data['mac']

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

    def run(self):

        if self.type == 'discover':
            self.dhcp_discover()
        elif self.type == 'offer':
            self.dhcp_offer()

        if self.type == 'request':
            self.dhcp_request()
        elif self.type == 'ack':
            self.dhcp_ack()


    def dhcp_discover(self):
        if self.pkt[Ether].src != self.mymac:
            self.check_dhcp_dos()
            return

        self.clear_record_discoffer()

        dhcp_discover_dicc = self.dhcp_discover_record.get()
        dhcp_discover_dicc[self.xid] = self.time_stamp

        file = self.dhcp_pkts_cache + self.xid + ' ' + self.time_stamp + ' discover.pcap'
        self.save_pkt(file)

        self.dhcp_discover_record.put(dhcp_discover_dicc)


    def dhcp_offer(self):
        if self.pkt[Ether].src == self.mymac:
            # print('DHCP protection: this offer is sended by me, im a dhcp server')
            return

        self.clear_record_discoffer()

        dhcp_discover_dicc = self.dhcp_discover_record.get()
        dhcp_offer_dicc = self.dhcp_offer_record.get()

        if (self.xid in dhcp_discover_dicc):
            time_stamp = dhcp_discover_dicc[self.xid]
            dhcp_offer_dicc[self.xid] = time_stamp
            dhcp_discover_dicc.pop(self.xid, None)
            file = self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' offer.pcap'
            self.save_pkt(file)
        else:
            if (self.xid in dhcp_offer_dicc):
                time_stamp = dhcp_offer_dicc[self.xid]
                pkt_discover = self.load_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' discover.pcap')[0]
                pkt_offer = self.load_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' offer.pcap')[0]
                log = Logger().write('DHCP rogue server, offers from ' + pkt_offer[Ether].src + ' and ' + self.pkt[Ether].src)
                Message().show(log)

                if self.config.get('DHCP protection', 'save_evidences') == 'True':
                    log = log.split('->')[0]# save evidences
                    pkts = [pkt_discover, pkt_offer, self.pkt]
                    file = 'data/evidences/' + log + '.pcap'
                    wrpcap(file, pkts)

                self.remove_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' discover.pcap')
                self.remove_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' offer.pcap')
                dhcp_offer_dicc.pop(self.xid, None)
            else:
                print('DHCP protection: offer whithout previous discover')

        self.dhcp_discover_record.put(dhcp_discover_dicc)
        self.dhcp_offer_record.put(dhcp_offer_dicc)



    def dhcp_request(self):
        if self.pkt[Ether].src != self.mymac:
            print('DHCP protection: this request is not mine maybe im a DHCP server')
            return

        self.clear_record_reqack()

        dhcp_request_dicc = self.dhcp_request_record.get()
        dhcp_request_dicc[self.xid] = self.time_stamp
        file = self.dhcp_pkts_cache + self.xid + ' ' + self.time_stamp + ' request.pcap'
        self.save_pkt(file)
        self.dhcp_request_record.put(dhcp_request_dicc)


    def dhcp_ack(self):
        if self.pkt[Ether].src == self.mymac:
            print('DHCP protection: this ack is sended by me, im a dhcp server')
            return

        self.clear_record_reqack()

        dhcp_request_dicc = self.dhcp_request_record.get()
        dhcp_ack_dicc = self.dhcp_ack_record.get()

        if (self.xid in dhcp_request_dicc):
            time_stamp = dhcp_request_dicc[self.xid]
            dhcp_ack_dicc[self.xid] = time_stamp
            dhcp_request_dicc.pop(self.xid, None)
            file = self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' ack.pcap'
            self.save_pkt(file)
        else:
            if (self.xid in dhcp_ack_dicc):
                time_stamp = dhcp_ack_dicc[self.xid]

                pkt_request = self.load_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' request.pcap')[0]
                pkt_ack = self.load_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' ack.pcap')[0]

                log = Logger().write('DHCP ack injection, acks from ' + pkt_ack[Ether].src + ' and ' + self.pkt[Ether].src)
                Message().show(log)

                if self.config.get('DHCP protection', 'save_evidences') == 'True':
                    log = log.split('->')[0]

                    pkts = [pkt_request, pkt_ack, self.pkt]
                    file = 'data/evidences/' + log + '.pcap'
                    wrpcap(file, pkts)

                self.remove_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' request.pcap')
                self.remove_pkt(self.dhcp_pkts_cache + self.xid + ' ' + time_stamp + ' ack.pcap')
                dhcp_ack_dicc.pop(self.xid, None)

            else:
                print('DHCP protection: ack whithout previous request')

        self.dhcp_request_record.put(dhcp_request_dicc)
        self.dhcp_ack_record.put(dhcp_ack_dicc)


    def check_dhcp_dos(self):
        dhcp_dos = self.dhcp_dos_record.get()

        if not dhcp_dos:
            dhcp_dos = [self.time_stamp, 1]
        else:
            time_stamp = dhcp_dos[0]

            fmt = '%Y-%m-%d %H:%M:%S'
            d1 = datetime.strptime(self.time_stamp, fmt)
            d2 = datetime.strptime(time_stamp, fmt)
            sec_difference = (d1 - d2).total_seconds()
            count = dhcp_dos[1]

            if sec_difference > int(self.config.get('DHCP protection', 'check_dhcp_dos_each')):

                if (count > int(self.config.get('DHCP protection', 'check_dhcp_dos_max_packets'))):
                    log = Logger().write('DHCP DOS, ' + str(count) + ' dicover in ' + str(self.config.get('DHCP protection','check_dhcp_dos_each')) + ' seconds')
                    Message().show(log)
                    if self.config.get('DHCP protection', 'save_evidences') == 'True':
                        log = log.split('->')[0]
                        file = 'data/evidences/' + log + '.pcap'
                        wrpcap(file, self.pkt)
                dhcp_dos = []
            else:
                count = count + 1
                dhcp_dos[1] = count

        self.dhcp_dos_record.put(dhcp_dos)


    def clear_record_discoffer(self):
        fmt = '%Y-%m-%d %H:%M:%S'
        d1 = datetime.strptime(self.time_stamp, fmt)
        dhcp_discover_dicc = self.dhcp_discover_record.get()
        dhcp_offer_dicc = self.dhcp_offer_record.get()
        discover_del_keys = []
        offer_del_keys = []

        for key, value in dhcp_discover_dicc.items():
            d2 = datetime.strptime(value, fmt)
            sec_difference = (d1 - d2).total_seconds()
            if  sec_difference > int(self.config.get('DHCP protection', 'keep_packets_cache')):
                discover_del_keys.append(key)
                file = self.dhcp_pkts_cache + key + ' ' + value + ' discover.pcap'
                self.remove_pkt(file)

        for key in discover_del_keys:
            dhcp_discover_dicc.pop(key, None)

        for key, value in dhcp_offer_dicc.items():
            d2 = datetime.strptime(value, fmt)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('DHCP protection', 'keep_packets_cache')):
                offer_del_keys.append(key)
                file = self.dhcp_pkts_cache + key + ' ' + value + ' discover.pcap'
                file1 = self.dhcp_pkts_cache + key + ' ' + value + ' offer.pcap'
                self.remove_pkt(file)
                self.remove_pkt(file1)

        for key in offer_del_keys:
            dhcp_offer_dicc.pop(key, None)

        self.dhcp_discover_record.put(dhcp_discover_dicc)
        self.dhcp_offer_record.put(dhcp_offer_dicc)


    def clear_record_reqack(self):
        fmt = '%Y-%m-%d %H:%M:%S'
        d1 = datetime.strptime(self.time_stamp, fmt)
        dhcp_request_dicc = self.dhcp_request_record.get()
        dhcp_ack_dicc = self.dhcp_ack_record.get()
        request_del_keys = []
        ack_del_keys = []

        for key, value in dhcp_request_dicc.items():
            d2 = datetime.strptime(value, fmt)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('DHCP protection', 'keep_packets_cache')):
                request_del_keys.append(key)
                file = self.dhcp_pkts_cache + key + ' ' + value + ' request.pcap'
                self.remove_pkt(file)

        for key in request_del_keys:
            dhcp_request_dicc.pop(key, None)

        for key, value in dhcp_ack_dicc.items():
            d2 = datetime.strptime(value, fmt)
            sec_difference = (d1 - d2).total_seconds()
            if sec_difference > int(self.config.get('DHCP protection', 'keep_packets_cache')):
                ack_del_keys.append(key)
                file = self.dhcp_pkts_cache + key + ' ' + value + ' request.pcap'
                file1 = self.dhcp_pkts_cache + key + ' ' + value + ' ack.pcap'
                self.remove_pkt(file)
                self.remove_pkt(file1)

        for key in ack_del_keys:
            dhcp_ack_dicc.pop(key, None)

        self.dhcp_request_record.put(dhcp_request_dicc)
        self.dhcp_ack_record.put(dhcp_ack_dicc)



    def save_pkt(self, file):
        self.dhcp_lock.acquire()
        try:
            wrpcap(file, self.pkt)
        finally:
            self.dhcp_lock.release()

    def load_pkt(self, file):
        self.dhcp_lock.acquire()
        pkt = None
        try:
            pkt = rdpcap(file)
        finally:
            self.dhcp_lock.release()
        return pkt

    def remove_pkt(self, file):
        self.dhcp_lock.acquire()
        try:
            os.remove(file)
        finally:
            self.dhcp_lock.release()

    @staticmethod
    def close(sniffer):
        dhcp_dos = sniffer.dhcp_dos_record.get()
        dhcp_dos = {}
        sniffer.dhcp_dos_record.put(dhcp_dos)

        dhcp_discover_dicc = sniffer.dhcp_discover_record.get()
        dhcp_discover_dicc = {}
        sniffer.dhcp_discover_record.put(dhcp_discover_dicc)

        dhcp_offer_dicc = sniffer.dhcp_offer_record.get()
        dhcp_offer_dicc = {}
        sniffer.dhcp_offer_record.put(dhcp_offer_dicc)

        dhcp_request_dicc = sniffer.dhcp_request_record.get()
        dhcp_request_dicc = {}
        sniffer.dhcp_request_record.put(dhcp_request_dicc)

        dhcp_ack_dicc = sniffer.dhcp_ack_record.get()
        dhcp_ack_dicc = {}
        sniffer.dhcp_ack_record.put(dhcp_ack_dicc)

        sniffer.dhcp_lock.acquire()
        try:
            for the_file in os.listdir('data/cache/dhcp_pkts/'):
                file_path = os.path.join('data/cache/dhcp_pkts/', the_file)
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                except Exception as e:
                    print(e)
        finally:
            sniffer.dhcp_lock.release()
