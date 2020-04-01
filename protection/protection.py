from arptable import *
from interface import *
from protection.reminder import *
from scapy.all import *
import configparser
from protection.arp_protection import *
from protection.arp_protection_init import *
from protection.dhcp_protection import *
from protection.llmnr_protection import *

class Protection(object):

    # Singelton - guardar instancia
    _instance = None

    # Singelton - asegurar singelton
    def __new__(self):
        if not self._instance:
            self._instance = super(Protection, self).__new__(self)
            self.reminder = Reminder()
        return self._instance

    # Iniciar Protección
    def start(self):
        print('protection start')

        # Cargar configuración
        self.config = configparser.ConfigParser()
        self.config.read('totem-hids.config')

        # obtener el nombre del interfaz
        interface = Interface().iface_name

        # Cargar sniffer - se lanza de forma asyncrona como un hilo
        self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, count=0)
        self.sniffer.start()

        # Lanzar los protection init
        if self.config['ARP protection']['check_arptable_on_start'] == 'True':
            ArpProtectionInit().start()


    def stop(self):
        print('protection stop')

        # Parar sniffer
        self.sniffer.stop()


    # Recibe los paquetes
    def packet_callback(self, pkt):

        if ARP in pkt and self.config.get('ARP protection','active') == 'True':
            snapshoot_ip_mac = {key: val for key, val in Arptable().ip_mac.items()}

            Arptable().update()

            arp_protection = ArpProtection(pkt, snapshoot_ip_mac)
            arp_protection.start()

        elif UDP in pkt and ((pkt[UDP].sport == 67 and pkt[UDP].dport == 68) or (pkt[UDP].sport == 68 and pkt[UDP].dport == 67)) and self.config.get('DHCP protection','active') == 'True':
            if not self.check_dhcp_starvation(pkt):
                dhcp_protection = Dhcp_protection(pkt)
                dhcp_protection.start()

        elif UDP in pkt and (pkt[UDP].sport == 5355 or pkt[UDP].dport == 5355) and self.config.get('LLMNR protection','active') == 'True':
            llmnr_protection = Llmnr_protection(pkt)
            llmnr_protection.start()

    def check_dhcp_starvation(self, pkt):
        type = Dhcp_protection.dhcp_types[pkt[DHCP].options[0][1]]
        if type == 'discover' or type == 'release':
            if Dhcp_protection.check_dhcp_starvation(pkt):
                return True
            return False
        else:
            return False

