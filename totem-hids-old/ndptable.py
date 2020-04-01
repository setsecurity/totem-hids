import subprocess
from interfaces import *

class Ndptable():

    _instance = None

    def __new__(self):
        if not self._instance:
            self._instance = super(Ndptable, self).__new__(self)
            self._instance.update()
        return self._instance

    def update(self):

        interfaces = Interfaces()
        interfaces.update()
        interface = interfaces.ifaces[interfaces.selected_index]

        cmd = 'ip -6 neighbor show'
        output = str(subprocess.check_output(cmd, shell=True))

        self.ip_mac = {}

        if output:

            ip_mac = {}
            output = output[2:]
            output = output[:-1]
            output = output.split('\\n')

            for line in output:
                if line:
                    line = line.split()
                    if len(line) == 6:
                        dev = line[2]
                        if dev == interface:
                            ip6 = line[0]
                            mac = line[4]
                            ip_mac[ip6] = mac

            self.ip_mac = ip_mac

