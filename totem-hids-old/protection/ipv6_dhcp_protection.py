import threading

class Ipv6_dhcp_protection(threading.Thread):


    def __init__(self, pkt):
        threading.Thread.__init__(self)

        self.pkt = pkt

    def run(self):
        hello = ''