import netifaces
from scapy.all import *

class Interfaces(object):

    _instance = None

    selected_index = 0

    def __new__(self):
        if not self._instance:
            self._instance = super(Interfaces, self).__new__(self)
            self._instance.iface_data = {}
            self._instance.update()
        return self._instance


    def update(self):
        self.ifaces = netifaces.interfaces()

        self.default_interface = conf.iface

        self.selected_index = self.ifaces.index(self.default_interface)

        selected_iface = self.ifaces[self.selected_index]

        data = netifaces.ifaddresses(selected_iface)
        mac = ''
        ip4 = ''
        broadcast4 = ''
        netmask4 = ''
        ip6 = ''
        netmask6 = ''
        ip6_link_local = ''
        netmask6_link_local = ''

        if(17 in data):
            mac = data[17][0]['addr']

        if(2 in data):
            ip4 = data[2][0]['addr']
            if 'broadcast' in data[2][0]: broadcast4 = data[2][0]['broadcast']
            netmask4 = data[2][0]['netmask']

        if(10 in data):
            if len(data[10]) == 1:
                ip6_link_local = data[10][0]['addr'].split('%')[0]
                netmask6_link_local = data[10][0]['netmask']
            else:
                ip6 = data[10][0]['addr']
                netmask6 = data[10][0]['netmask']

                ip6_link_local = data[10][1]['addr'].split('%')[0]
                netmask6_link_local = data[10][1]['netmask']

        self.iface_data = {'ip4':ip4,'mac':mac,'netmask4':netmask4,'broadcast4':broadcast4,'ip6':ip6,'netmask6':netmask6,'ip6_link_local':ip6_link_local,'netmask6_link_local':netmask6_link_local}

        self.gdata = netifaces.gateways()

        self.default_ip4_gateway = []
        self.default_ip6_gateway = []

        if 'default' in self.gdata:
            if 2 in self.gdata['default']:
                self.default_ip4_gateway.append(self.gdata['default'][netifaces.AF_INET][1])
                self.default_ip4_gateway.append(self.gdata['default'][netifaces.AF_INET][0])
            if 10 in self.gdata['default']:
                self.default_ip6_gateway.append(self.gdata['default'][netifaces.AF_INET6][1])
                self.default_ip6_gateway.append(self.gdata['default'][netifaces.AF_INET6][0])



