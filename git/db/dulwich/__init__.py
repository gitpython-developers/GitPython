"""Dulwich module initialization"""

def init_dulwich():
	""":raise ImportError: if dulwich is not present"""
	try:
		import dulwich
	except ImportError:
		raise ImportError("Could not find 'dulwich' in the PYTHONPATH - dulwich functionality is not available")
	#END handle dulwich import



init_dulwich()
