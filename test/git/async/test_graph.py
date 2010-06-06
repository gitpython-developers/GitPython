"""Channel testing"""
from test.testlib import *
from git.async.graph import *

import time

class TestGraph(TestBase):
	
	def test_base(self):
		g = Graph()
		nn = 10
		assert nn > 2, "need at least 3 nodes"
		
		# add unconnected nodes
		for i in range(nn):
			assert isinstance(g.add_node(Node()), Node)
		# END add nodes
		assert len(g.nodes) == nn
		
		# delete unconnected nodes
		for n in g.nodes[:]:
			g.del_node(n)
		# END del nodes
		
		# add a chain of connected nodes
		last = None
		for i in range(nn):
			n = g.add_node(Node(i))
			if last:
				assert not last.out_nodes
				assert not n.in_nodes
				assert g.add_edge(last, n) is g
				assert last.out_nodes[0] is n
				assert n.in_nodes[0] is last
			last = n
		# END for each node to connect
		
		# try to connect a node with itself
		self.failUnlessRaises(ValueError, g.add_edge, last, last)
		
		# try to create a cycle
		self.failUnlessRaises(ValueError, g.add_edge, g.nodes[0], g.nodes[-1])
		self.failUnlessRaises(ValueError, g.add_edge, g.nodes[-1], g.nodes[0])
		
		# we have undirected edges, readding the same edge, but the other way
		# around does not change anything
		n1, n2, n3 = g.nodes[0], g.nodes[1], g.nodes[2] 
		g.add_edge(n1, n2)		# already connected
		g.add_edge(n2, n1)		# same thing
		assert len(n1.out_nodes) == 1
		assert len(n1.in_nodes) == 0
		assert len(n2.in_nodes) == 1
		assert len(n2.out_nodes) == 1
			
		# deleting a connected node clears its neighbour connections
		assert n3.in_nodes[0] is n2
		assert g.del_node(n2) is g
		assert g.del_node(n2) is g					# multi-deletion okay
		assert len(g.nodes) == nn - 1
		assert len(n3.in_nodes) == 0
		assert len(n1.out_nodes) == 0
		
		# check the history from the last node
		last = g.nodes[-1]
		class Visitor(object):
			def __init__(self, origin):
				self.origin_seen = False
				self.origin = origin
				self.num_seen = 0
				
			def __call__(self, n):
				if n is self.origin:
					self.origin_seen = True
				else:
					assert not self.origin_seen, "should see origin last"
				# END check origin 
				self.num_seen += 1
				return True
				
			def _assert(self, num_expected):
				assert self.origin_seen
				assert self.num_seen == num_expected
		# END visitor helper
		
		end = g.nodes[-1] 
		visitor = Visitor(end)
		g.visit_input_inclusive_depth_first(end, visitor)
		
		num_nodes_seen = nn - 2		# deleted second, which leaves first one disconnected
		visitor._assert(num_nodes_seen)
		
