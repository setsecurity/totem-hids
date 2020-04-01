import queue
import threading

class Reminder(object):

    # Singelton - guardar instancia
    _instance = None

    # Singelton - asegurar singelton
    def __new__(self):
        if not self._instance:
            self._instance = super(Reminder, self).__new__(self)

            # diccionario queue ARP spam - {MAC -> [timestamp, Count] }
            # contar num de paquetes ARP desde un mismo origen en X tiempo
            # MAC origen , tiemstamp primer paquete ARP desde un origen MAC, Cuenta de paquetes recibidos desde ese origen MAC
            arp_spam_dicc = {}
            self.arp_spam_record = queue.Queue()
            self.arp_spam_record.put(arp_spam_dicc)


            # diccionarios  queue de paquetes DHCP por tipos
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

            dhcp_dos = []
            self.dhcp_dos_record = queue.Queue()
            self.dhcp_dos_record.put(dhcp_dos)

            llmr_ip4_dicc = {}
            self.llmr_ip4_record = queue.Queue()
            self.llmr_ip4_record.put(llmr_ip4_dicc)

            llmr_ip6_dicc = {}
            self.llmr_ip6_record = queue.Queue()
            self.llmr_ip6_record.put(llmr_ip6_dicc)

        return self._instance
