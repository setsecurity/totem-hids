from python_arptable import *
from interface import *

# instalar librería python_arptable en el sistema, en nuestro caso para python3
# sudo python3 -m pip install python_arptable

class Arptable(object):

    # Singelton - guardar instancia
    _instance = None

    # Singelton - asegurar singelton
    def __new__(self):
        if not self._instance:
            self._instance = super(Arptable, self).__new__(self)
            self._instance.update()
        return self._instance



    def update(self):

        # Interfaz de red
        interface = Interface().iface_name

        # Diccionario donde guadar entradas ARP: IP <-> MAC
        ip_mac = {}

        # Obtener tabla ARP con la librería python_arptable
        self.arptable = get_arp_table()

        # Guardar en el diccionario, las entradas asociadas al interfaz de red donde se realiza la protección
        for i in self.arptable:
            if i['Device'] == interface:
                ip_mac[i['IP address']] = i['HW address']
        self.ip_mac = ip_mac

