# README


Proyect Totem-HIDS for fun and profit.


Its a python3 Host IDS that detects network spoofing attacks.


Notes:
* This project is not stable, do not use it in production.
* The objetive of this proyect is research and testing.
* This project is not maintained.
* All effort goes to the Totem Network IDS version (coming soon).


Installation:
* sudo apt install python3 python3-dev
* sudo apt install python3-pip
* sudo python3 -m pip install python_arptable
* sudo python3 -m pip install scapy (2.4.3.dev0)
* sudo python3 -m pip install netifaces

Usage:
* python3 main.py eth0


POCs:
* ARP spoogin: https://www.youtube.com/watch?v=xKs0nUS4kVY
* DHCP ACK injection: https://www.youtube.com/watch?v=SLm385BowaY


Detected attacks:
* ARP spoofing
* DHCP rogue server
* DHCP ACK injection
* DHCP Starvation
* LLMNR spoofing
* LLMNR WPAD spoofing

Old version detected attacks (deprecated):
* ARP spoofing
* DHCP rogue server
* DHCP ACK injection
* DHCP Starvation
* LLMNR spoofing
* LLMNR WPAD spoofing
* Netbios spoofing
* IPv6 NDP spoofing
* IPv6 SLAAC attack
* IPv6 DHCP rogue server

Old POCs:
* https://www.youtube.com/watch?v=r7DxZAyjUAw
* https://www.youtube.com/watch?v=XpEQNY0ozAE


