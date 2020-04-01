from arptable import *
from interface import *
from logger import *
from protection.reminder import *
from protection.protection import *
import time
import sys

# Inicializar info del interfaz de red seleccionado
Interface()
Interface().assign_iface(sys.argv[1])
Interface().update()

# Inicializar tabla ARP
Arptable()

# Inicializar Logger
Logger()

# Inicializar Memory
Reminder()

Protection().start()

while(True):
    time.sleep(1)
