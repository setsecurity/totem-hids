import threading
import time
from interfaces import *

class Ipv6_slaac_updater(threading.Thread):

    def __init__(self,slaac_attack_on):
        threading.Thread.__init__(self)
        self.slaac_attack_on = slaac_attack_on

    def run(self):
        slaac_attack = self.slaac_attack_on.get()
        self.slaac_attack_on.put(slaac_attack)
        if slaac_attack:
            time.sleep(10)
            interfaces = Interfaces()
            interfaces.update()
            ip6 = interfaces.iface_data['ip6']
            print(ip6)
            if ip6 == '':
                slaac_attack = self.slaac_attack_on.get()
                slaac_attack = False
                self.slaac_attack_on.put(slaac_attack)

