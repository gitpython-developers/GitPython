"""Simplistic implementation of a graph"""

__all__ = ('Node', 'Graph')

class Node(object):
	"""A Node in the graph. They know their neighbours, and have an id which should 
	resolve into a string"""
	__slots__ = ('in_nodes', 'out_nodes', 'id')
	
	def __init__(self, id=None):
		self.id = id
		self.in_nodes = list()
		self.out_nodes = list()
		
	def __str__(self):
		return str(self.id)
		
	def __repr__(self):
		return "%s(%s)" % (type(self).__name__, self.id)
	
	
class Graph(object):
	"""A simple graph implementation, keeping nodes and providing basic access and 
	editing functions. The performance is only suitable for small graphs of not 
	more than 10 nodes !"""
	__slots__ = "nodes"
	
	def __init__(self):
		self.nodes = list()

	def __del__(self):
		"""Deletes bidericational dependencies"""
		for node in self.nodes:
			node.in_nodes = None
			node.out_nodes = None
		# END cleanup nodes
		
		# otherwise the nodes would keep floating around
	

	def add_node(self, node):
		"""Add a new node to the graph
		:return: the newly added node"""
		self.nodes.append(node)
		return node
	
	def remove_node(self, node):
		"""Delete a node from the graph
		:return: self"""
		try:
			del(self.nodes[self.nodes.index(node)])
		except ValueError:
			return self
		# END ignore if it doesn't exist
		
		# clear connections
		for outn in node.out_nodes:
			del(outn.in_nodes[outn.in_nodes.index(node)])
		for inn in node.in_nodes:
			del(inn.out_nodes[inn.out_nodes.index(node)])
		node.out_nodes = list()
		node.in_nodes = list()
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
	
	def input_inclusive_dfirst_reversed(self, node):
		"""Return all input nodes of the given node, depth first,
		It will return the actual input node last, as it is required
		like that by the pool"""
		stack = [node]
		seen = set()
		
		# depth first
		out = list()
		while stack:
			n = stack.pop()
			if n in seen:
				continue
			seen.add(n)
			out.append(n)
			
			# only proceed in that direction if visitor is fine with it
			stack.extend(n.in_nodes)
			# END call visitor
		# END while walking
		out.reverse()
		return out
		
