"""Simplistic implementation of a graph"""

class Node(object):
	"""A quick and dirty to the point implementation of a simple, and slow ascyclic graph.
	Its not designed to support big graphs, and sports only the functionality 
	we need"""
	__slots__ = ('in_nodes', 'out_nodes')
	
	
class Graph(object):
	"""A simple graph implementation, keeping nodes and providing basic access and 
	editing functions"""
	__slots__ = "nodes"
	
	def __init__(self):
		self.nodes = list()
	
	def add_node(self, node):
		"""Add a new node to the graph"""
		raise NotImplementedError()
	
	def del_node(self, node):
		"""Delete a node from the graph"""
		raise NotImplementedError()
	
	def add_edge(self, u, v):
		"""Add an undirected edge between the given nodes u and v.
		:raise ValueError: If the new edge would create a cycle"""
		raise NotImplementedError()
	
	def visit_input_depth_first(self, node, visitor=lambda n: True ):
		"""Visit all input nodes of the given node, depth first, calling visitor
		for each node on our way. If the function returns False, the traversal 
		will not go any deeper, but continue at the next branch"""
		raise NotImplementedError()

