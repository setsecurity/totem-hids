import threading
import queue
import configparser
from scapy.all import *
from interfaces import *
from ndptable import *
from protection.arp_protection import *
from protection.dhcp_protection import *
from protection.llmnr_protection import *
from protection.ipv6_slaac_protection import *
from protection.ipv6_slaac_updater import *
from protection.ipv6_ndp_protection import *
from protection.ipv6_dhcp_protection import *


class Sniffer(threading.Thread):

    stop = False

    def __init__(self):
        threading.Thread.__init__(self)

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        arp_spam_dicc = {}
        self.arp_spam_record = queue.Queue()
        self.arp_spam_record.put(arp_spam_dicc)

        dhcp_discover_dicc = {}
        self.dhcp_discover_record = queue.Queue()
        self.dhcp_discover_record.put(dhcp_discover_dicc)

        dhcp_offer_dicc = {}
        self.dhcp_offer_record = queue.Queue()
        self.dhcp_offer_record.put(dhcp_offer_dicc)

        dhcp_request_dicc = {}
        self.dhcp_request_record = queue.Queue()
        self.dhcp_request_record.put(dhcp_request_dicc)

        dhcp_ack_dicc = {}
        self.dhcp_ack_record = queue.Queue()
        self.dhcp_ack_record.put(dhcp_ack_dicc)

        dhcp_dos = {}
        self.dhcp_dos_record = queue.Queue()
        self.dhcp_dos_record.put(dhcp_dos)

        self.dhcp_lock = threading.Lock()

        llmnr_ip4_dicc = {}
        self.llmnr_ip4_record = queue.Queue()
        self.llmnr_ip4_record.put(llmnr_ip4_dicc)

        llmnr_ip6_dicc = {}
        self.llmnr_ip6_record = queue.Queue()
        self.llmnr_ip6_record.put(llmnr_ip6_dicc)

        llmnr_spoofed = []
        self.llmnr_spoofed = queue.Queue()
        self.llmnr_spoofed.put(llmnr_spoofed)

        wpad_spoofed = []
        self.wpad_spoofed = queue.Queue()
        self.wpad_spoofed.put(wpad_spoofed)

        self.llmnr_lock = threading.Lock()

        slaac_attack = False
        self.slaac_attack_on = queue.Queue()
        self.slaac_attack_on.put(slaac_attack)

        ndp_spam_dicc = {}
        self.ndp_spam_record = queue.Queue()
        self.ndp_spam_record.put(ndp_spam_dicc)

        ndp_spoof_dicc = {}
        self.ndp_spoof_record = queue.Queue()
        self.ndp_spoof_record.put(ndp_spoof_dicc)

    def run(self):
        self.interfaces = Interfaces()
        self.interfaces.update()
        interface = self.interfaces.ifaces[self.interfaces.selected_index]

        self.stop = False
        sniff(iface=interface,prn=self.packet_callback,count=0,stop_filter=self.stop_filter)

    def packet_callback(self, pkt):
        if ARP in pkt and self.config.get('ARP protection','active') == 'True':
            snapshoot_ip_mac = {key:val for key,val in Arptable().ip_mac.items()}
            Arptable().update()
            arp_protection = Arp_protection(pkt,snapshoot_ip_mac,self.arp_spam_record)
            arp_protection.start()

        elif UDP in pkt and ((pkt[UDP].sport == 67 and pkt[UDP].dport == 68) or (pkt[UDP].sport == 68 and pkt[UDP].dport == 67)) and self.config.get('DHCP protection','active') == 'True':
            dhcp_protection = Dhcp_protection(pkt,self.dhcp_discover_record,self.dhcp_offer_record,self.dhcp_request_record,self.dhcp_ack_record, self.dhcp_lock, self.dhcp_dos_record)
            dhcp_protection.start()

        #elif UDP in pkt and (pkt[UDP].sport == 137 or pkt[UDP].dport == 137) and self.config.get('NetBios protection','active') == 'True':
            #netbios_protection = Netbios_protection(pkt,self.netbios_query_record,self.netbios_response_record,self.netbios_lock)
            #netbios_protection.start()

        elif UDP in pkt and (pkt[UDP].sport == 5355 or pkt[UDP].dport == 5355) and self.config.get('LLMNR protection', 'active') == 'True':
            llmnr_protection = Llmnr_protection(pkt,self.llmnr_ip4_record,self.llmnr_ip6_record,self.llmnr_spoofed,self.llmnr_lock,self.wpad_spoofed,self.ndp_spoof_record)
            llmnr_protection.start()

        elif IPv6 in pkt and pkt.haslayer(ICMPv6ND_RA) and self.config.get('SLAAC protection', 'active') == 'True':
            iface_data_snapshoot = {key:val for key,val in Interfaces().iface_data.items()}
            ipv6_slaac_protection = Ipv6_slaac_protection(pkt,iface_data_snapshoot,self.slaac_attack_on)
            ipv6_slaac_protection.start()

            slaack_attack = self.slaac_attack_on.get()
            self.slaac_attack_on.put(slaack_attack)
            if slaack_attack: Ipv6_slaac_updater(self.slaac_attack_on).start()

        elif IPv6 in pkt and (pkt.haslayer(ICMPv6ND_NA) or pkt.haslayer(ICMPv6ND_NS)) and self.config.get('NDP protection', 'active') == 'True':
            snapshoot_ip_mac = {key: val for key, val in Ndptable().ip_mac.items()}
            Ndptable().update()
            ipv6_ndp_protection = Ipv6_ndp_protection(pkt,snapshoot_ip_mac,self.ndp_spam_record,self.ndp_spoof_record)
            ipv6_ndp_protection.start()

        elif IPv6 in pkt and UDP in pkt and ((pkt[UDP].sport == 547 and pkt[UDP].dport == 546) or (pkt[UDP].sport == 546 and pkt[UDP].dport == 547)) and self.config.get('DHCPV6 protection','active') == 'True':
            ipv6_dhcp_protection = Ipv6_dhcp_protection(pkt)
            ipv6_dhcp_protection.start()


    def stop_filter(self,pkt):
        return self.stop