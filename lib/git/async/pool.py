"""Implementation of a thread-pool working with channels"""
from thread import (
		WorkerThread, 
		StopProcessing,
		)
from threading import Lock

from util import (
		AsyncQueue,
		DummyLock
	)

from task import InputChannelTask
from Queue import (
	Queue, 
	Empty
	)

from graph import Graph 
from channel import (
		mkchannel,
		WChannel, 
		SerialWChannel,
		RChannel
	)

import sys
from time import sleep


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
		del(self._wc)		# decrement ref-count early
		# now, if this is the last reader to the wc we just handled, there 
		# is no way anyone will ever read from the task again. If so, 
		# delete the task in question, it will take care of itself and orphans
		# it might leave
		# 1 is ourselves, + 1 for the call + 1, and 3 magical ones which 
		# I can't explain, but appears to be normal in the destructor
		# On the caller side, getrefcount returns 2, as expected
		if sys.getrefcount(self) < 6:
			self._pool.remove_task(self._task)
		# END handle refcount based removal of task
	
	def set_pre_cb(self, fun = lambda count: None):
		"""Install a callback to call with the item count to be read before any 
		item is actually  read from the channel. The call must be threadsafe if
		the channel is passed to more than one tasks.
		If it fails, the read will fail with an IOError
		If a function is not provided, the call is effectively uninstalled."""
		self._pre_cb = fun
	
	def set_post_cb(self, fun = lambda item: item):
		"""Install a callback to call after the items were read. The function
		returns a possibly changed item list.The call must be threadsafe if
		the channel is passed to more than one tasks. 
		If it raises, the exception will be propagated.
		If a function is not provided, the call is effectively uninstalled."""
		self._post_cb = fun
	
	def read(self, count=0, block=True, timeout=None):
		"""Read an item that was processed by one of our threads
		:note: Triggers task dependency handling needed to provide the necessary 
			input"""
		if self._pre_cb:
			self._pre_cb()
		# END pre callback
		
		# NOTE: we always queue the operation that would give us count items
		# as tracking the scheduled items or testing the channels size
		# is in herently unsafe depending on the design of the task network
		# If we put on tasks onto the queue for every request, we are sure
		# to always produce enough items, even if the task.min_count actually
		# provided enough - its better to have some possibly empty task runs 
		# than having and empty queue that blocks.
		
		# NOTE: TODO: that case is only possible if one Task could be connected 
		# to multiple input channels in a manner known by the system. Currently
		# this is not possible, but should be implemented at some point 
		
		# if the user tries to use us to read from a done task, we will never 
		# compute as all produced items are already in the channel
		skip_compute = self._task.is_done() or self._task.error()
		
		########## prepare ##############################
		if not skip_compute:
			self._pool._prepare_channel_read(self._task, count)
		# END prepare pool scheduling
		
		
		####### read data ########
		##########################
		# read actual items, tasks were setup to put their output into our channel ( as well )
		items = RChannel.read(self, count, block, timeout)
		##########################
		
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
	
	
class Pool(object):
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
					'_num_workers',			# list of workers
					'_queue', 				# master queue for tasks
					'_taskorder_cache', 	# map task id -> ordered dependent tasks
					'_taskgraph_lock',		# lock for accessing the task graph
				)
	
	# CONFIGURATION
	# The type of worker to create - its expected to provide the Thread interface, 
	# taking the taskqueue as only init argument
	# as well as a method called stop_and_join() to terminate it
	WorkerCls = None
	
	# The type of lock to use to protect critical sections, providing the 
	# threading.Lock interface
	LockCls = None
	
	# the type of the task queue to use - it must provide the Queue interface
	TaskQueueCls = None
	
	
	def __init__(self, size=0):
		self._tasks = Graph()
		self._num_workers = 0
		self._queue = self.TaskQueueCls()
		self._taskgraph_lock = self.LockCls()
		self._taskorder_cache = dict()
		self.set_size(size)
		
	def __del__(self):
		self.set_size(0)
	
	#{ Internal
		
	def _prepare_channel_read(self, task, count):
		"""Process the tasks which depend on the given one to be sure the input 
		channels are filled with data once we process the actual task
		
		Tasks have two important states: either they are done, or they are done 
		and have an error, so they are likely not to have finished all their work.
		
		Either way, we will put them onto a list of tasks to delete them, providng 
		information about the failed ones.
		
		Tasks which are not done will be put onto the queue for processing, which 
		is fine as we walked them depth-first."""
		# for the walk, we must make sure the ordering does not change. Even 
		# when accessing the cache, as it is related to graph changes
		self._taskgraph_lock.acquire()
		try:
			try:
				dfirst_tasks = self._taskorder_cache[id(task)]
			except KeyError:
				# have to retrieve the list from the graph
				dfirst_tasks = list()
				self._tasks.visit_input_inclusive_depth_first(task, lambda n: dfirst_tasks.append(n))
				self._taskorder_cache[id(task)] = dfirst_tasks
			# END handle cached order retrieval
		finally:
			self._taskgraph_lock.release()
		# END handle locking
		
		# check the min count on all involved tasks, and be sure that we don't 
		# have any task which produces less than the maximum min-count of all tasks
		# The actual_count is used when chunking tasks up for the queue, whereas 
		# the count is usued to determine whether we still have enough output
		# on the queue, checking qsize ( ->revise )
		# ABTRACT: If T depends on T-1, and the client wants 1 item, T produces
		# at least 10, T-1 goes with 1, then T will block after 1 item, which 
		# is read by the client. On the next read of 1 item, we would find T's 
		# queue empty and put in another 10, which could put another thread into 
		# blocking state. T-1 produces one more item, which is consumed right away
		# by the two threads running T. Although this works in the end, it leaves
		# many threads blocking and waiting for input, which is not desired.
		# Setting the min-count to the max of the mincount of all tasks assures
		# we have enough items for all.
		# Addition: in serial mode, we would enter a deadlock if one task would
		# ever wait for items !
		actual_count = count
		min_counts = (((t.min_count is not None and t.min_count) or count) for t in dfirst_tasks)
		min_count = reduce(lambda m1, m2: max(m1, m2), min_counts)
		if 0 < count < min_count:
			actual_count = min_count
		# END set actual count
		
		# the list includes our tasks - the first one to evaluate first, the 
		# requested one last
		for task in dfirst_tasks: 
			# if task.error() or task.is_done():
				# in theory, the should never be consumed task in the pool, right ?
				# They delete themselves once they are done. But as we run asynchronously, 
				# It can be that someone reads, while a task realizes its done, and 
				# we get here to prepare the read although it already is done.
				# Its not a problem though, the task wiill not do anything.
				# Hence we don't waste our time with checking for it
				# raise AssertionError("Shouldn't have consumed tasks on the pool, they delete themeselves, what happend ?")
			# END skip processing
			
			# but use the actual count to produce the output, we may produce 
			# more than requested
			numchunks = 1
			chunksize = actual_count
			remainder = 0
			
			# we need the count set for this - can't chunk up unlimited items
			# In serial mode we could do this by checking for empty input channels, 
			# but in dispatch mode its impossible ( == not easily possible )
			# Only try it if we have enough demand
			if task.max_chunksize and actual_count > task.max_chunksize:
				numchunks = actual_count / task.max_chunksize
				chunksize = task.max_chunksize
				remainder = actual_count - (numchunks * chunksize)
			# END handle chunking
			
			# the following loops are kind of unrolled - code duplication
			# should make things execute faster. Putting the if statements 
			# into the loop would be less code, but ... slower
			# DEBUG
			# print actual_count, numchunks, chunksize, remainder, task._out_wc.size()
			if self._num_workers:
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
		# END for each task to process
		
		
	def _post_channel_read(self, task):
		"""Called after we processed a read to cleanup"""
		pass
	
	def _remove_task_if_orphaned(self, task):
		"""Check the task, and delete it if it is orphaned"""
		# 1 as its stored on the task, 1 for the getrefcount call
		if sys.getrefcount(task._out_wc) < 3:
			self.remove_task(task)
	#} END internal
	
	#{ Interface 
	def size(self):
		""":return: amount of workers in the pool
		:note: method is not threadsafe !"""
		return self._num_workers
	
	def set_size(self, size=0):
		"""Set the amount of workers to use in this pool. When reducing the size, 
		threads will continue with their work until they are done before effectively
		being removed.
		
		:return: self
		:param size: if 0, the pool will do all work itself in the calling thread, 
			otherwise the work will be distributed among the given amount of threads.
			If the size is 0, newly added tasks will use channels which are NOT 
			threadsafe to optimize item throughput.
		
		:note: currently NOT threadsafe !"""
		assert size > -1, "Size cannot be negative"
		
		# either start new threads, or kill existing ones.
		# If we end up with no threads, we process the remaining chunks on the queue
		# ourselves
		cur_count = self._num_workers
		if cur_count < size:
			# we can safely increase the size, even from serial mode, as we would
			# only be able to do this if the serial ( sync ) mode finished processing.
			# Just adding more workers is not a problem at all.
			add_count = size - cur_count
			for i in range(add_count):
				self.WorkerCls(self._queue).start()
			# END for each new worker to create
			self._num_workers += add_count
		elif cur_count > size:
			# We don't care which thread exactly gets hit by our stop request
			# On their way, they will consume remaining tasks, but new ones 
			# could be added as we speak.
			del_count = cur_count - size
			for i in range(del_count):
				self._queue.put((self.WorkerCls.stop, True))	# arg doesnt matter
			# END for each thread to stop
			self._num_workers -= del_count
		# END handle count
		
		if size == 0:
			# NOTE: we do not preocess any tasks still on the queue, as we ill 
			# naturally do that once we read the next time, only on the tasks
			# that are actually required. The queue will keep the tasks, 
			# and once we are deleted, they will vanish without additional
			# time spend on them. If there shouldn't be any consumers anyway.
			# If we should reenable some workers again, they will continue on the 
			# remaining tasks, probably with nothing to do.
			# We can't clear the task queue if we have removed workers 
			# as they will receive the termination signal through it, and if 
			# we had added workers, we wouldn't be here ;).
			pass 
		# END process queue
		return self
		
	def num_tasks(self):
		""":return: amount of tasks"""
		self._taskgraph_lock.acquire()
		try:
			return len(self._tasks.nodes)
		finally:
			self._taskgraph_lock.release()
		
	def remove_task(self, task):
		"""Delete the task
		Additionally we will remove orphaned tasks, which can be identified if their 
		output channel is only held by themselves, so no one will ever consume 
		its items.
		
		This method blocks until all tasks to be removed have been processed, if 
		they are currently being processed.
		:return: self"""
		self._taskgraph_lock.acquire()
		try:
			# it can be that the task is already deleted, but its chunk was on the 
			# queue until now, so its marked consumed again
			if not task in self._tasks.nodes:
				return self
			# END early abort
			
			# the task we are currently deleting could also be processed by 
			# a thread right now. We don't care about it as its taking care about
			# its write channel itself, and sends everything it can to it.
			# For it it doesn't matter that its not part of our task graph anymore.
		
			# now delete our actual node - be sure its done to prevent further 
			# processing in case there are still client reads on their way.
			task.set_done()
			
			# keep its input nodes as we check whether they were orphaned
			in_tasks = task.in_nodes
			self._tasks.del_node(task)
			self._taskorder_cache.clear()
		finally:
			self._taskgraph_lock.release()
		# END locked deletion
		
		for t in in_tasks:
			self._remove_task_if_orphaned(t)
		# END handle orphans recursively
		
		return self
	
	def add_task(self, task):
		"""Add a new task to be processed.
		:return: a read channel to retrieve processed items. If that handle is lost, 
			the task will be considered orphaned and will be deleted on the next 
			occasion."""
		# create a write channel for it
		wctype = WChannel
		
		self._taskgraph_lock.acquire()
		try:
			self._taskorder_cache.clear()
			self._tasks.add_node(task)
			
			# fix locks - in serial mode, the task does not need real locks
			# Additionally, use a non-threadsafe queue
			# This brings about 15% more performance, but sacrifices thread-safety
			# when reading from multiple threads.
			if self.size() == 0:
				wctype = SerialWChannel
			# END improve locks
			
			# setup the tasks channel
			wc = wctype()
			rc = RPoolChannel(wc, task, self)
			task.set_wc(wc)
		finally:
			self._taskgraph_lock.release()
		# END sync task addition
		
		# If the input channel is one of our read channels, we add the relation
		if isinstance(task, InputChannelTask):
			ic = task.in_rc
			if isinstance(ic, RPoolChannel) and ic._pool is self:
				self._taskgraph_lock.acquire()
				try:
					self._tasks.add_edge(ic._task, task)
				finally:
					self._taskgraph_lock.release()
				# END handle edge-adding
			# END add task relation
		# END handle input channels for connections
		
		return rc
			
	#} END interface 
	
	
class ThreadPool(Pool):
	"""A pool using threads as worker"""
	WorkerCls = WorkerThread
	LockCls = Lock
	TaskQueueCls = AsyncQueue
