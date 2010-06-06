"""Implementation of a thread-pool working with channels"""
from thread import WorkerThread
from task import InputChannelTask
from Queue import Queue

from graph import (
		Graph, 
	)

from channel import (
		Channel,
		WChannel, 
		RChannel
	)

import weakref
import sys


class RPoolChannel(RChannel):
	""" A read-only pool channel may not be wrapped or derived from, but it provides slots to call
	before and after an item is to be read.
	
	It acts like a handle to the underlying task in the pool."""
	__slots__ = ('_task', '_pool', '_pre_cb', '_post_cb')
	
	def __init__(self, wchannel, task, pool):
		RChannel.__init__(self, wchannel)
		self._task = task
		self._pool = pool
		self._pre_cb = None
		self._post_cb = None
		
	def __del__(self):
		"""Assures that our task will be deleted if we were the last reader"""
		del(self._wc)		# decrement ref-count
		self._pool._del_task_if_orphaned(self._task)
	
	def set_pre_cb(self, fun = lambda count: None):
		"""Install a callback to call with the item count to be read before any 
		item is actually  read from the channel.
		If it fails, the read will fail with an IOError
		If a function is not provided, the call is effectively uninstalled."""
		self._pre_cb = fun
	
	def set_post_cb(self, fun = lambda item: item):
		"""Install a callback to call after the items were read. The function
		returns a possibly changed item list. If it raises, the exception will be propagated.
		If a function is not provided, the call is effectively uninstalled."""
		self._post_cb = fun
		
	def read(self, count=0, block=True, timeout=None):
		"""Read an item that was processed by one of our threads
		:note: Triggers task dependency handling needed to provide the necessary 
			input"""
		if self._pre_cb:
			self._pre_cb()
		# END pre callback
		
		########## prepare ##############################
		self._pool._prepare_channel_read(self._task, count)
		
		
		######### read data ######
		# read actual items, tasks were setup to put their output into our channel ( as well )
		items = RChannel.read(self, count, block, timeout)
		
		if self._post_cb:
			items = self._post_cb(items)
			
		
		####### Finalize ########
		self._pool._post_channel_read(self._task)
			
		return items
		
	#{ Internal
	def _read(self, count=0, block=False, timeout=None):
		"""Calls the underlying channel's read directly, without triggering 
		the pool"""
		return RChannel.read(self, count, block, timeout)
	
	#} END internal
	
	
class ThreadPool(object):
	"""A thread pool maintains a set of one or more worker threads, but supports 
	a fully serial mode in which case the amount of threads is zero.
	
	Work is distributed via Channels, which form a dependency graph. The evaluation
	is lazy, as work will only be done once an output is requested.
	
	The thread pools inherent issue is the global interpreter lock that it will hit, 
	which gets worse considering a few c extensions specifically lock their part
	globally as well. The only way this will improve is if custom c extensions
	are written which do some bulk work, but release the GIL once they have acquired
	their resources.
	
	Due to the nature of having multiple objects in git, its easy to distribute 
	that work cleanly among threads.
	
	:note: the current implementation returns channels which are meant to be 
		used only from the main thread, hence you cannot consume their results 
		from multiple threads unless you use a task for it."""
	__slots__ = (	'_tasks',				# a graph of tasks
					'_consumed_tasks',		# a list with tasks that are done or had an error
					'_workers',				# list of worker threads
					'_queue', 				# master queue for tasks
				)
	
	def __init__(self, size=0):
		self._tasks = Graph()
		self._consumed_tasks = list()
		self._workers = list()
		self._queue = Queue()
		self.set_size(size)
		
	def __del__(self):
		self.set_size(0)
	
	#{ Internal
	def _queue_feeder_visitor(self, task, count):
		"""Walk the graph and find tasks that are done for later cleanup, and 
		queue all others for processing by our worker threads ( if available )."""
		if task.error() or task.is_done():
			self._consumed_tasks.append(task)
			return True
		# END stop processing
		
		# if the task does not have the required output on its queue, schedule
		# it for processing. If we should process all, we don't care about the 
		# amount as it should process until its all done.
		if count < 1 or task._out_wc.size() < count:
			# allow min-count override. This makes sure we take at least min-count
			# items off the input queue ( later )
			if task.min_count is not None and 0 < count < task.min_count:
				count = task.min_count
			# END handle min-count
			
			numchunks = 1
			chunksize = count
			remainder = 0
			
			# we need the count set for this - can't chunk up unlimited items
			# In serial mode we could do this by checking for empty input channels, 
			# but in dispatch mode its impossible ( == not easily possible )
			# Only try it if we have enough demand
			if task.max_chunksize and count > task.max_chunksize:
				numchunks = count / task.max_chunksize
				chunksize = task.max_chunksize
				remainder = count - (numchunks * chunksize)
			# END handle chunking
			
			# the following loops are kind of unrolled - code duplication
			# should make things execute faster. Putting the if statements 
			# into the loop would be less code, but ... slower
			print count, numchunks, chunksize, remainder, task._out_wc.size()
			if self._workers:
				# respect the chunk size, and split the task up if we want 
				# to process too much. This can be defined per task
				queue = self._queue
				if numchunks > 1:
					for i in xrange(numchunks):
						queue.put((task.process, chunksize))
					# END for each chunk to put
				else:
					queue.put((task.process, chunksize))
				# END try efficient looping
				
				if remainder:
					queue.put((task.process, remainder))
				# END handle chunksize
			else:
				# no workers, so we have to do the work ourselves
				if numchunks > 1:
					for i in xrange(numchunks):
						task.process(chunksize)
					# END for each chunk to put
				else:
					task.process(chunksize)
				# END try efficient looping
				
				if remainder:
					task.process(remainder)
				# END handle chunksize
			# END handle serial mode
		# END handle queuing 
		
		# always walk the whole graph, we want to find consumed tasks
		return True
		
	def _prepare_channel_read(self, task, count):
		"""Process the tasks which depend on the given one to be sure the input 
		channels are filled with data once we process the actual task
		
		Tasks have two important states: either they are done, or they are done 
		and have an error, so they are likely not to have finished all their work.
		
		Either way, we will put them onto a list of tasks to delete them, providng 
		information about the failed ones.
		
		Tasks which are not done will be put onto the queue for processing, which 
		is fine as we walked them depth-first."""
		self._tasks.visit_input_inclusive_depth_first(task, lambda n: self._queue_feeder_visitor(n, count))
		
	def _post_channel_read(self, task):
		"""Called after we processed a read to cleanup"""
		# check whether we consumed the task, and schedule it for deletion
		if task.error() or task.is_done():
			self._consumed_tasks.append(task)
		# END handle consumption
		
		# delete consumed tasks to cleanup
		for task in self._consumed_tasks:
			self.del_task(task)
		# END for each task to delete
		
		del(self._consumed_tasks[:])
		
	def _del_task_if_orphaned(self, task):
		"""Check the task, and delete it if it is orphaned"""
		if sys.getrefcount(task._out_wc) < 3:
			self.del_task(task)
	#} END internal
	
	#{ Interface 
	def size(self):
		""":return: amount of workers in the pool"""
		return len(self._workers)
	
	def set_size(self, size=0):
		"""Set the amount of workers to use in this pool. When reducing the size, 
		the call may block as it waits for threads to finish. 
		When reducing the size to zero, this thread will process all remaining 
		items on the queue.
		
		:return: self
		:param size: if 0, the pool will do all work itself in the calling thread, 
			otherwise the work will be distributed among the given amount of threads"""
		# either start new threads, or kill existing ones.
		# If we end up with no threads, we process the remaining chunks on the queue
		# ourselves
		cur_count = len(self._workers)
		if cur_count < size:
			for i in range(size - cur_count):
				worker = WorkerThread(self._queue)
				worker.start()
				self._workers.append(worker)
			# END for each new worker to create
		elif cur_count > size:
			del_count = cur_count - size
			for i in range(del_count):
				self._workers[i].stop_and_join()
			# END for each thread to stop
			del(self._workers[:del_count])
		# END handle count
		
		if size == 0:
			while not self._queue.empty():
				try:
					taskmethod, count = self._queue.get(False)
					taskmethod(count)
				except Queue.Empty:
					continue
			# END while there are tasks on the queue
		# END process queue
		return self
		
	def num_tasks(self):
		""":return: amount of tasks"""
		return len(self._tasks.nodes)
		
	def del_task(self, task):
		"""Delete the task
		Additionally we will remove orphaned tasks, which can be identified if their 
		output channel is only held by themselves, so no one will ever consume 
		its items.
		
		:return: self"""
		# now delete our actual node - must set it done os it closes its channels.
		# Otherwise further reads of output tasks will block.
		# Actually they may still block if anyone wants to read all ... without 
		# a timeout
		# keep its input nodes as we check whether they were orphaned
		in_tasks = task.in_nodes
		task.set_done()
		self._tasks.del_node(task)
		
		for t in in_tasks:
			self._del_task_if_orphaned(t)
		# END handle orphans recursively
		
		return self
	
	def add_task(self, task):
		"""Add a new task to be processed.
		:return: a read channel to retrieve processed items. If that handle is lost, 
			the task will be considered orphaned and will be deleted on the next 
			occasion."""
		# create a write channel for it
		wc, rc = Channel()
		rc = RPoolChannel(wc, task, self)
		task._out_wc = wc
		
		has_input_channel = isinstance(task, InputChannelTask) 
		if has_input_channel:
			task._pool_ref = weakref.ref(self)
		# END init input channel task
		
		self._tasks.add_node(task)
		
		# If the input channel is one of our read channels, we add the relation
		if has_input_channel:
			ic = task.in_rc
			if isinstance(ic, RPoolChannel) and ic._pool is self:
				self._tasks.add_edge(ic._task, task)
			# END add task relation
		# END handle input channels for connections
		
		return rc
			
	#} END interface 
