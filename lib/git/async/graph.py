"""Simplistic implementation of a graph"""

class Node(object):
	"""A quick and dirty to the point implementation of a simple, and slow ascyclic graph.
	Its not designed to support big graphs, and sports only the functionality 
	we need"""
	__slots__ = ('in_nodes', 'out_nodes')
	
	def __init__(self):
		self.in_nodes = list()
		self.out_nodes = list()
	
	
class Graph(object):
	"""A simple graph implementation, keeping nodes and providing basic access and 
	editing functions. The performance is only suitable for small graphs of not 
	more than 10 nodes !"""
	__slots__ = "nodes"
	
	def __init__(self):
		self.nodes = list()
	
	def add_node(self, node):
		"""Add a new node to the graph
		:return: the newly added node"""
		self.nodes.append(node)
		return node
	
	def del_node(self, node):
		"""Delete a node from the graph
		:return: self"""
		# clear connections
		for outn in node.out_nodes:
			del(outn.in_nodes[outn.in_nodes.index(node)])
		for inn in node.in_nodes:
			del(inn.out_nodes[inn.out_nodes.index(node)])
		del(self.nodes[self.nodes.index(node)]) 
		return self
	
	def add_edge(self, u, v):
		"""Add an undirected edge between the given nodes u and v.
		
		return: self
		:raise ValueError: If the new edge would create a cycle"""
		if u is v:
			raise ValueError("Cannot connect a node with itself")
		
		# are they already connected ?
		if 	u in v.in_nodes and v in u.out_nodes or \
			v in u.in_nodes and u in v.out_nodes:
			return self
		# END handle connection exists
		
		# cycle check - if we can reach any of the two by following either ones 
		# history, its a cycle
		for start, end in ((u, v), (v,u)):
			if not start.in_nodes: 
				continue
			nodes = start.in_nodes[:]
			seen = set()
			# depth first search - its faster
			while nodes:
				n = nodes.pop()
				if n in seen:
					continue
				seen.add(n)
				if n is end:
					raise ValueError("Connecting u with v would create a cycle")
				nodes.extend(n.in_nodes)
			# END while we are searching
		# END for each direction to look
		
		# connection is valid, set it up
		u.out_nodes.append(v)
		v.in_nodes.append(u)
		
		return self
	
	def visit_input_inclusive_depth_first(self, node, visitor=lambda n: True ):
		"""Visit all input nodes of the given node, depth first, calling visitor
		for each node on our way. If the function returns False, the traversal 
		will not go any deeper, but continue at the next branch
		It will return the actual input node in the end !"""
		nodes = node.in_nodes[:]
		seen = set()
		
		# depth first
		while nodes:
			n = nodes.pop()
			if n in seen:
				continue
			seen.add(n)
			
			# only proceed in that direction if visitor is fine with it
			if visitor(n):
				nodes.extend(n.in_nodes)
			# END call visitor
		# END while walking
		visitor(node)
		
