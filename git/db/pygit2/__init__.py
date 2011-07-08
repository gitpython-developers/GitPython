"""Pygit2 module initialization"""

def init_pygit2():
	""":raise ImportError: if pygit2 is not present"""
	try:
		import pygit2
	except ImportError:
		raise ImportError("Could not find 'pygit2' in the PYTHONPATH - pygit2 functionality is not available")
	#END handle pygit2 import

init_pygit2()
