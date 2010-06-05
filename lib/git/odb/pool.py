"""Implementation of a thread-pool working with channels"""
from thread import TerminatableThread
from channel import (
		Channel,
		WChannel, 
		RChannel
	)

class Node(object):
	"""A quick and dirty to the point implementation of a simple, and slow ascyclic graph.
	Its not designed to support big graphs, and sports only the functionality 
	we need"""
	__slots__('in_nodes', 'out_nodes')
	
	
class Graph(object):
	"""A simple graph implementation, keeping nodes and providing basic access and 
	editing functions"""
	__slots__ = "nodes"
	
	def add_node(self, node):
		pass
	
	def del_node(self, node):
		pass
	
	def visit_input_depth_first(self, node, visitor=lambda n: True ):
		"""Visit all input nodes of the given node, depth first, calling visitor
		for each node on our way. If the function returns False, the traversal 
		will not go any deeper, but continue at the next branch"""
		pass
	

class TaskNode(Node):
	"""Couples an input channel, an output channel, as well as a processing function
	together.
	It may contain additional information on how to handel read-errors from the
	input channel"""
	__slots__ = ('in_rc', 'out_wc', 'fun')
	
	def is_done(self):
		""":return: True if we are finished processing"""
		return self.out_wc.closed 


class PoolChannel(Channel):
	"""Base class for read and write channels which trigger the pool to evaluate
	its tasks, causing the evaluation of the task list effectively assure a read
	from actual output channel will not block forever due to task dependencies.
	"""
	__slots__ = tuple()
	
	
class RPoolChannel(PoolChannel):
	""" A read-only pool channel may not be wrapped or derived from, but it provides slots to call
	before and after an item is to be read"""
	__slots__ = ('_task', '_pool', '_pre_cb', '_post_cb')
	
	def set_post_cb(self, fun = lambda item: item):
		"""Install a callback to call after the item has been read. The function
		returns a possibly changed item. If it raises, the exception will be propagated
		in an IOError, indicating read-failure
		If a function is not provided, the call is effectively uninstalled."""
		
	def set_pre_cb(self, fun = lambda : None):
		"""Install a callback to call before an item is read from the channel.
		If it fails, the read will fail with an IOError
		If a function is not provided, the call is effectively uninstalled."""
	

class PoolWorker(WorkerThread):
	"""A worker thread which gets called to deal with Tasks. Tasks provide channls
	with actual work, whose result will be send to the tasks output channel"""

	@classmethod
	def perform_task(cls, task):
		pass
	
	
class ThreadPool(Graph):
	"""A thread pool maintains a set of one or more worker threads, but supports 
	a fully serial mode in which case the amount of threads is zero.
	
	Work is distributed via Channels, which form a dependency graph. The evaluation
	is lazy, as work will only be done once an output is requested."""
	__slots__ = (	'_workers',				# list of worker threads
					'_queue', 				# master queue for tasks
					'_ordered_tasks_cache' # tasks in order of evaluation, mapped by read channel
				)
	
	def del_node(self, task):
		"""Delete the node ( being a task ), but delete the entries in our output channel 
		cache as well"""
		
	
	def set_pool_size(self, size=0):
		"""Set the amount of workers to use in this pool.
		:param size: if 0, the pool will do all work itself in the calling thread, 
			otherwise the work will be distributed among the given amount of threads"""
			
	def add_task(self, task):
		"""Add a new task to be processed.
		:return: your task instance with its output channel set. It can be used 
			to retrieve processed items"""
