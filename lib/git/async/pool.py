"""Implementation of a thread-pool working with channels"""
from thread import WorkerThread
from threading import Lock

from util import (
		SyncQueue,
		AsyncQueue,
	)

from task import InputChannelTask
from Queue import (
	Queue, 
	Empty
	)

from graph import Graph 
from channel import (
		Channel,
		WChannel, 
		RChannel
	)

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
		
		# if we have count items, don't do any queue preparation - if someone
		# depletes the queue in the meanwhile, the channel will close and 
		# we will unblock naturally
		have_enough = False
		if count > 0:
			# explicitly > count, as we want a certain safe range
			have_enough = self._wc._queue.qsize() > count
		# END risky game
		
		########## prepare ##############################
		if not have_enough:
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
					'_consumed_tasks',		# a queue with tasks that are done or had an error
					'_workers',				# list of worker threads
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
		self._consumed_tasks = None
		self._workers = list()
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
			if task.error() or task.is_done():
				self._consumed_tasks.put(task)
				continue
			# END skip processing
			
			# if the task does not have the required output on its queue, schedule
			# it for processing. If we should process all, we don't care about the 
			# amount as it should process until its all done.
			#if count > 1 and task._out_wc.size() >= count:
			#	continue
			# END skip if we have enough
			
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
		# END for each task to process
		
		
	def _post_channel_read(self, task):
		"""Called after we processed a read to cleanup"""
		# check whether we consumed the task, and schedule it for deletion
		# This could have happend after the read returned ( even though the pre-read 
		# checks it as well )
		if task.error() or task.is_done():
			self._consumed_tasks.put(task)
		# END handle consumption
		
		self._handle_consumed_tasks()

	def _handle_consumed_tasks(self):
		"""Remove all consumed tasks from our queue by deleting them"""
		try:
			while True:
				ct = self._consumed_tasks.get(False)
				self.del_task(ct)
			# END for each task to delete
		except Empty:
			pass
		# END pop queue empty

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
			otherwise the work will be distributed among the given amount of threads
		
		:note: currently NOT threadsafe !"""
		assert size > -1, "Size cannot be negative"
		
		# either start new threads, or kill existing ones.
		# If we end up with no threads, we process the remaining chunks on the queue
		# ourselves
		cur_count = len(self._workers)
		if cur_count < size:
			# make sure we have a real queue, and can store our consumed tasks properly
			if not isinstance(self._consumed_tasks, self.TaskQueueCls):
				self._consumed_tasks = Queue()
			# END init queue
			
			for i in range(size - cur_count):
				worker = self.WorkerCls(self._queue)
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
			
			if self._consumed_tasks and not self._consumed_tasks.empty(): 
				self._handle_consumed_tasks()
			# END assure consumed tasks are empty
			self._consumed_tasks = SyncQueue()
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
		
		This method blocks until all tasks to be removed have been processed, if 
		they are currently being processed.
		:return: self"""
		# now delete our actual node - must set it done os it closes its channels.
		# Otherwise further reads of output tasks will block.
		# Actually they may still block if anyone wants to read all ... without 
		# a timeout
		# keep its input nodes as we check whether they were orphaned
		in_tasks = task.in_nodes
		task.set_done()
		self._taskgraph_lock.acquire()
		try:
			self._taskorder_cache.clear()
			# before we can delete the task, make sure its write channel 
			# is closed, otherwise people might still be waiting for its result.
			# If a channel is not closed, this could also mean its not yet fully
			# processed, but more importantly, there must be no task being processed
			# right now.
			# TODO: figure this out
			for worker in self._workers:
				r = worker.routine()
				if r and r.im_self is task:
					raise NotImplementedError("todo")
				# END handle running task
			# END check for in-progress routine
			
			# its done, close the channel for writing
			task.close()
			self._tasks.del_node(task)
		finally:
			self._taskgraph_lock.release()
		# END locked deletion
		
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
		task.set_wc(wc)
		
		has_input_channel = isinstance(task, InputChannelTask) 
		if has_input_channel:
			task.set_pool(self)
		# END init input channel task
		
		self._taskgraph_lock.acquire()
		try:
			self._taskorder_cache.clear()
			self._tasks.add_node(task)
		finally:
			self._taskgraph_lock.release()
		# END sync task addition 
		
		# If the input channel is one of our read channels, we add the relation
		if has_input_channel:
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
