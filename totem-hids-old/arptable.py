from python_arptable import *
from interfaces import *

class Arptable(object):

    _instance = None

    def __new__(self):
        if not self._instance:
            self._instance = super(Arptable, self).__new__(self)
            self._instance.update()
        return self._instance

    def update(self):
        ip_mac = {}
        self.arptable = get_arp_table()

        interfaces = Interfaces()
        interfaces.update()
        interface = interfaces.ifaces[interfaces.selected_index]

        for i in self.arptable:
            if i['Device'] == interface:
                ip_mac[i['IP address']] = i['HW address']
        self.ip_mac = ip_mac
