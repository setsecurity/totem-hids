from kivy.uix.popup import *
from kivy.uix.label import *
from kivy.uix.boxlayout import *
import configparser
import re


class Message():
    _instance = None

    def __new__(self):
        if not self._instance:
            self._instance = super(Message, self).__new__(self)
            self._instance.load()
        return self._instance

    def load(self):
        self.user_descriptions = {
            'ARP poisoning': 'Your network comunications are been monitored by an attacker.',
            'ARP spam': 'An attacker is unsuccesfully trying to monitorize your comunications, you are save but the attacker may try some other attacks.',
            'DHCP rogue server': 'Your network comunications are been monitored by an attacker.',
            'DHCP ack injection': 'Your network comunications are been monitored by an attacker.',
            'DHCP DOS': 'An attacker is performing an attack to monitorize comunications in your network.',
            'NDP poisoning': 'Your ipv6 network comunications are been monitored.',
            'NDP spam': 'An attacker is unsuccesfully trying to monitorize your ipv6 comunications.',
            'IPv6 attack': 'Posible ipv6 attack, all your comunications are using ipv6.',
            'IPv6 setup': 'Posible ipv6 attack, your ipv6 configuration is up.',
            'ICMPv6 SLAAC attack': 'Ipv6 attack, all your comunications are using ipv6.',
            'ICMPv6 RA set up ipv6 address': 'Ipv6 attack, your ipv6 configuration is up.',
            'LLMNR ipv4 spoof': 'You are accesing to a rogue host.',
            'LLMNR WPAD response': 'Your web comunications are been monitored.',
            'LLMNR ipv6 spoof': 'You are accesing to a rogue host.',
            'The ipv6 of LLMNR query is spoofed': 'You are accesing to a rogue host.'
        }

        self.user_contrameasure = {
            'ARP poisoning': 'Disconnect from the network to prevent risks.',
            'ARP spam': 'Disconnect from the network to prevent risks.',
            'DHCP rogue server': 'Disconnect from the network to prevent risks.',
            'DHCP ack injection': 'Disconnect from the network to prevent risks.',
            'DHCP DOS': 'Disconnect from the network to prevent risks.',
            'NDP poisoning': 'Desactivate ipv6 configuration.',
            'NDP spam': 'Desactivate ipv6 configuration.',
            'IPv6 attack': 'Desactivate ipv6 configuration.',
            'IPv6 setup': 'Desactivate ipv6 configuration.',
            'ICMPv6 SLAAC attack': 'Desactivate ipv6 configuration.',
            'ICMPv6 RA set up ipv6 address': 'Desactivate ipv6 configuration.',
            'LLMNR ipv4 spoof': 'Disconnect from the host.',
            'LLMNR WPAD response': 'Configure your browser without proxy.',
            'LLMNR ipv6 spoof': 'Disconnect from the host.',
            'The ipv6 of LLMNR query is spoofed': 'Disconnect from the host.'
        }

        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

    def show(self,log):

        user_mode = False
        if self.config.get('General', 'mode') == 'User': user_mode = True


        log = log.replace('[','')
        log = log.replace(']', '')
        log = log.split('->')

        title = log[0]
        msg = log[1]

        box = BoxLayout(orientation='vertical')
        attack = msg.split(',')[0].strip()
        msg = re.sub("(.{50})", "\\1\n", msg, 0, re.DOTALL)

        contra = self.user_contrameasure[attack]
        contra = re.sub("(.{50})", "\\1\n", contra, 0, re.DOTALL)


        if user_mode:
            title = title.split(' ')
            title = title[0] + title[1] +' '+ attack

            description = self.user_descriptions[attack]
            description = re.sub("(.{50})", "\\1\n", description, 0, re.DOTALL)

            box.add_widget(Label(text=msg))
            box.add_widget(Label(text=description))
            box.add_widget(Label(text=contra))

        else:
            box.add_widget(Label(text=msg))
            box.add_widget(Label(text=contra))
            box.add_widget(Label(text='Evidences:\n/totem/data/evidences/'+title+'.*',font_size ='13sp'))

        popup = Popup(title=title, content=box, size_hint=(None, None), size=(400, 400))
        popup.open()

