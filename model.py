
class DefaultModel():

	def __init__(self):
		pass
	
	# load model from file
	def load_from_disk(self):
		pass

	# save current state of the model to a file
	def save_to_disk(self):
		pass

	# return the current client list
	def get_client_list(self):
		pass
	
	# return a client's network list
	def get_network_list(self, client):
		pass
	
	# associate networks to their known locations via external API
	def geolocate_networks(self, network_list):
		pass
