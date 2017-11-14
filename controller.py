
class ZahoriController:
	
	def __init__(self,model,view):
		self.model = model
		#self.model.add_observer(self)
		self.view = view
		self.view.set_controller(self)

	# listener for scan results
	def scanner_notify(event):
		event_type, args = event
		if event_type == 0: # new scan result
			client_bssid, network_bssid = args
			if network_ssid:
				if client_bssid in self.clients.keys():
					if network_ssid not in self.clients[client_bssid]:
						self.clients[client_bssid].append(network_ssid)
				else:
					self.clients[client_bssid] = [network_ssid]
		elif event_type == 1: # scan failure
			pass

	# scan for new clients using specified interface
	def scan(self, interface, timeout, channels):
		pass
