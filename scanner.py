import os
import time
from threading import Thread
import pyric             # pyric errors
import pyric.pyw as pyw  # iw functionality
from scapy.all import sniff, Dot11ProbeReq, Dot11, Dot11Elt

class ChannelHopper(Thread):
	'''I'm not documenting this but it's really pretty obvious.'''

	def __init__(self, interface, delay=1, channels=[1,6,11,2,7,12,3,8,13,4,9]):
		super().__init__()
		self._running = True
		self._delay = delay
		self._channels = channels
		self._interface = interface

	def channel_hopping(self):
		i = 0
		while self._running:
			pyw.chset(self._interface, self._channels[i], None)
			i += 1
			i %= len(self._channels)
			time.sleep(self._delay)

	def run(self):
		self.channel_hopping()

	def stop(self):
		self._running = False

class Scanner(Thread):
	''' Scanner class, handles scanner runs including setting up a monitor and
disposing of it when not necessary anymore.
	# event type	  meaning
	EV_SCAN_OK		- scan finished ok (EV_SCAN_OK)
	EV_SCAN_FAILED	- scan terminated with errors (EV_SCAN_FAILED, reason)
	EV_SCAN_RESULTS	- newly scanned information (EV_SCAN_RESULTS, results)

	get_wireless_interfaces()	- returns available interfaces for monitoring
	Scanner(iface_name)			- creates a new scanner on the provided interface
	add_observer(observer)		- adds an observer
	scan(timeout=10)			- makes an scan run until timeout seconds run out'''

	# event type	  code	meaning
	EV_SCAN_OK 		= 0		# scan finished ok (EV_SCAN_OK)
	EV_SCAN_FAILED	= 1		# scan terminated with errors (EV_SCAN_FAILED, reason)
	EV_SCAN_RESULTS = 2		# newly scanned information (EV_SCAN_RESULTS, results)
	
	_MON_NAME = "mon0"

	# return available radio interfaces
	def get_wireless_interfaces():
		return pyw.winterfaces()

	def __init__(self, iface_name):
		super().__init__()
		self._HANDLER = self._make_handler()
		self._abort = False
		self._observers = []
		self._monitor = None
		self._iface_name = iface_name
		self._iface = pyw.getcard(iface_name)
		self._timeout = 0
		
	def add_observer(self,observer):
		self._observers.append(observer)

	def _notify_observers(self,event):
		[o.scanner_notify(event) for o in self._observers]
	
	_LFILTER=lambda pkt: pkt.haslayer(Dot11ProbeReq)
	
	def _stop_filter(self, dummy):
		return self._abort
	
	def _make_handler(self):
		def handler(pkt):
			client_bssid = pkt[Dot11].addr2
			try:
				network_ssid = pkt[Dot11Elt].info.decode('utf-8','replace')
				msg = client_bssid, network_ssid
				self._notify_observers((Scanner.EV_SCAN_RESULTS, msg))
			except UnicodeDecodeError:
				pass # TODO: log this
		return handler
	
	def run(self):
		self._abort = False
		hopper = None
		try:
			# set up monitor
			self._monitor = pyw.devadd(self._iface, Scanner._MON_NAME, 'monitor')
			for card,dev in pyw.ifaces(self._monitor):
				if card.dev != self._monitor.dev:
					pyw.devdel(card)
			pyw.up(self._monitor)
			self._iface = None
			
			# set up channel hopping
			hopper = ChannelHopper(self._monitor)
			hopper.start()
		
			sniff(iface=Scanner._MON_NAME,
				store=0,
				prn=self._HANDLER,
				lfilter=Scanner._LFILTER,
				timeout=self._timeout,
				stop_filter=self._stop_filter)
			self._notify_observers((Scanner.EV_SCAN_OK))
		except pyric.error as e:
			self._notify_observers((Scanner.EV_SCAN_FAILED, e))
		finally:
			if hopper:
				# stop channel hopping
				hopper.stop()
			if self._monitor:
				# destroy monitor interface
				self._iface = pyw.devadd(self._monitor, self._iface_name, 'managed')
				pyw.devdel(self._monitor)
				pyw.up(self._iface)
				self._monitor = None
	
	def scan(self,timeout=10):
		self._timeout = timeout
		self.start()
	
	def stop(self):
		if self.is_alive():
			self._abort = True

