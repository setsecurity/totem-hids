from kivy.app import App
from kivy.core.window import Window
from protection.protection import *
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from kivy.uix.togglebutton import ToggleButton


Builder.load_string("""
<Totem>:
	BoxLayout:
		orientation: 'horizontal'
		canvas.before:
			Rectangle:
				pos: self.pos
				size: self.size
				source: 'gui/computers.jpg'
		BoxLayout:
			Spinner:
				id: spinner
				text: root.ifaces_names_gui[root.interfaces.selected_index]
				values: root.ifaces_names_gui
				size_hint_y: .25
				pos_hint: {'x': 0, 'y': .75}
				on_text: root.spinner_selection(spinner.text)



		BoxLayout:
			orientation: 'vertical'


			Switch:
				id: switch
				pos_hint: {'x': 0, 'y': 0}
				on_active: root.switch_action(switch.active, spinner)

			BoxLayout:
				size_hint_y: .7

				Button:
					text: 'Config'
					on_press: root.manager.current = 'config'
					size_hint_y: .5
					size_hint_x: .5
					pos_hint: {'x': 0, 'y': 0}
<ConfigScreen>:
    GridLayout:
        cols: 2
		BoxLayout:
		    Label:
		        text: 'Alerts:'
            ToggleButton:
                id: expert
                text: 'Expert'
                group: 'mode'
                state: root.load_mode_config_user()
            ToggleButton:
                id: user
                text: 'User'
                group: 'mode'
                state: root.load_mode_config_expert()
        BoxLayout:
		    Label:
		        text: 'ARP protection: '
            Switch:
                id: arp
                active: root.load_arp_config()
        BoxLayout:
		    Label:
		        text: 'DHCP protection: '
            Switch:
                id: dhcp
                active: root.load_dhcp_config()
        BoxLayout:
		    Label:
		        text: 'LLMNR protection: '
            Switch:
                id: llmnr
                active: root.load_llmnr_config()
        BoxLayout:
		    Label:
		        text: 'WPAD protection: '
            Switch:
                id: wpad
                active: root.load_wpad_config()
        BoxLayout:
		    Label:
		        text: 'SLAAC protection: '
            Switch:
                id: slaac
                active: root.load_slaac_config()
        BoxLayout:
		    Label:
		        text: 'NDP protection: '
            Switch:
                id: ndp
                active: root.load_ndp_config()
        BoxLayout:
		    Label:
		        text: 'IPv6 init protection: '
            Switch:
                id: ipv6_init
                active: root.load_ipv6init_config()

        Button:
            text: 'Back'
            on_press: root.manager.current = 'totem'
        Button:
            text: 'Save'
            on_press: root.save(user.state,arp.active,dhcp.active,llmnr.active,wpad.active,slaac.active,ndp.active,ipv6_init.active)

""")




class Totem(Screen):

    def __init__(self, **kwargs):


        self.interfaces = Interfaces()
        self.protection = Protection()

        self.ifaces_names_gui = []
        for value in self.interfaces.ifaces:
            default = False
            if value == self.interfaces.default_interface: default = True

            if value == 'lo':
                if default: self.ifaces_names_gui.append('loopback (default) - '+value)
                else: self.ifaces_names_gui.append('loopback - '+value)
            elif value.startswith('wlp'):
                if default: self.ifaces_names_gui.append('wifi (default) - '+value)
                else: self.ifaces_names_gui.append('wifi - '+value)
            elif value.startswith('enp'):
                if default: self.ifaces_names_gui.append('cable (default) - '+value)
                else: self.ifaces_names_gui.append('cable - '+value)
            else:
                self.ifaces_names_gui.append(value)

        super(Totem, self).__init__(**kwargs)
        Window.size = (600, 400)
        pass

    def spinner_selection(self,text):
        text = text.split('-')
        if len(text) > 1: text = text[1].strip()
        else: text = text[0].strip()
        index = self.interfaces.ifaces.index(text)
        self.interfaces.selected_index = index

    def switch_action(self,state,spinner):
        if(state):
            spinner.disabled = True
            self.protection.start()
        else:
            spinner.disabled = False
            self.protection.stop()

class ConfigScreen(Screen):
    def __init__(self, **kwargs):
        self.config = configparser.ConfigParser()
        self.config.read('totem.config')

        super(ConfigScreen, self).__init__(**kwargs)
        Window.size = (600, 400)
        pass

    def load_mode_config_user(self):
        if self.config.get('General', 'mode') == 'User': return 'down'
        else: return 'normal'

    def load_mode_config_expert(self):
        if self.config.get('General', 'mode') == 'Expert': return 'down'
        else: return 'normal'

    def load_arp_config(self):
        if self.config.get('ARP protection', 'active') == 'True': return True
        else: return False

    def load_dhcp_config(self):
        if self.config.get('DHCP protection', 'active') == 'True': return True
        else: return False

    def load_llmnr_config(self):
        if self.config.get('LLMNR protection', 'active') == 'True': return True
        else: return False

    def load_wpad_config(self):
        if self.config.get('WPAD protection', 'active') == 'True': return True
        else: return False

    def load_slaac_config(self):
        if self.config.get('SLAAC protection', 'active') == 'True': return True
        else: return False

    def load_ndp_config(self):
        if self.config.get('NDP protection', 'active') == 'True': return True
        else: return False

    def load_ipv6init_config(self):
        if self.config.get('IPV6 protection init', 'active') == 'True': return True
        else: return False

    def save(self,user,arp,dhcp,llmnr,wpad,slaac,ndp,ipv6_init):
        if user == 'down': self.config.set('General', 'mode', 'User')
        else: self.config.set('General', 'mode', 'Expert')

        if arp: self.config.set('ARP protection', 'active', 'True')
        else: self.config.set('ARP protection', 'active', 'False')

        if dhcp: self.config.set('DHCP protection', 'active', 'True')
        else: self.config.set('DHCP protection', 'active', 'False')

        if llmnr: self.config.set('LLMNR protection', 'active', 'True')
        else: self.config.set('LLMNR protection', 'active', 'False')

        if wpad: self.config.set('WPAD protection', 'active', 'True')
        else: self.config.set('WPAD protection', 'active', 'False')

        if slaac: self.config.set('SLAAC protection', 'active', 'True')
        else: self.config.set('SLAAC protection', 'active', 'False')

        if ndp: self.config.set('NDP protection', 'active', 'True')
        else: self.config.set('NDP protection', 'active', 'False')

        if ipv6_init: self.config.set('IPV6 protection init', 'active', 'True')
        else: self.config.set('IPV6 protection init', 'active', 'False')

        with open('totem.config', 'w') as file:
            self.config.write(file)

#Create the screen manager
sm = ScreenManager()
sm.add_widget(Totem(name='totem'))
sm.add_widget(ConfigScreen(name='config'))


class Gui(App):
    icon = 'totem.png'
    title = 'Totem'

    def build(self):
        return sm

    def on_stop(self):
        self.protection = Protection()
        self.protection.stop()
