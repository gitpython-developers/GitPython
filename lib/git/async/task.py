from graph import Node

import threading
import weakref
import sys
import new

class OutputChannelTask(Node):
	"""Abstracts a named task as part of a set of interdependent tasks, which contains 
	additional information on how the task should be queued and processed.
	
	Results of the item processing are sent to an output channel, which is to be 
	set by the creator
	
	* **min_count** assures that not less than min_count items will be processed per call.
	* **max_chunksize** assures that multi-threading is happening in smaller chunks. If 
	 someone wants all items to be processed, using read(0), the whole task would go to
	 one worker, as well as dependent tasks. If you want finer granularity , you can 
	 specify this here, causing chunks to be no larger than max_chunksize"""
	__slots__ = (	'_read',			# method to yield items to process 
					'_out_wc', 			# output write channel
					'_exc',				# exception caught
					'_done',			# True if we are done
					'_scheduled_items', # amount of scheduled items that will be processed in total
					'_slock',			# lock for scheduled items
					'fun',				# function to call with items read
					'min_count', 		# minimum amount of items to produce, None means no override
					'max_chunksize',	# maximium amount of items to process per process call
					'apply_single'		# apply single items even if multiple where read
					)
	
	def __init__(self, id, fun, apply_single=True, min_count=None, max_chunksize=0):
		Node.__init__(self, id)
		self._read = None					# to be set by subclasss 
		self._out_wc = None					# to be set later
		self._exc = None
		self._done = False
		self._scheduled_items = 0
		self._slock = threading.Lock()
		self.fun = fun
		self.min_count = None
		self.max_chunksize = 0				# note set
		self.apply_single = apply_single
	
	def is_done(self):
		""":return: True if we are finished processing"""
		return self._done
		
	def set_done(self):
		"""Set ourselves to being done, has we have completed the processing"""
		self._done = True
		
	def set_wc(self, wc):
		"""Set the write channel to the given one
		:note: resets it done state in order to allow proper queue handling"""
		self._done = False
		self._scheduled_items = 0
		self._out_wc = wc
		
	def close(self):
		"""A closed task will close its channel to assure the readers will wake up
		:note: its safe to call this method multiple times"""
		self._out_wc.close()
		
	def is_closed(self):
		""":return: True if the task's write channel is closed"""
		return self._out_wc.closed
		
	def error(self):
		""":return: Exception caught during last processing or None"""
		return self._exc

	def add_scheduled_items(self, count):
		"""Add the given amount of scheduled items to this task"""
		self._slock.acquire()
		self._scheduled_items += count 
		self._slock.release()
		
	def scheduled_item_count(self):
		""":return: amount of scheduled items for this task"""
		self._slock.acquire()
		try:
			return self._scheduled_items
		finally:
			self._slock.release()
		# END threadsafe return

	def process(self, count=0):
		"""Process count items and send the result individually to the output channel"""
		items = self._read(count)
		print "task read", len(items)
		try:
			# increase the ref-count - we use this to determine whether anyone else
			# is currently handling our output channel. As this method runs asynchronously, 
			# we have to make sure that the channel is closed by the last finishing task,
			# which is not necessarily the one which determines that he is done
			# as he couldn't read anymore items.
			# The refcount will be dropped in the moment we get out of here.
			wc = self._out_wc
			if self.apply_single:
				for item in items:
					rval = self.fun(item)
					# decrement afterwards, the its unscheduled once its produced  
					self._slock.acquire()
					self._scheduled_items -= 1
					self._slock.release()
					wc.write(rval)
				# END for each item
			else:
				# shouldn't apply single be the default anyway ? 
				# The task designers should chunk them up in advance
				rvals = self.fun(items)
				self._slock.acquire()
				self._scheduled_items -= len(items)
				self._slock.release()
				for rval in rvals:
					wc.write(rval)
			# END handle single apply
		except Exception, e:
			self._exc = e
			print str(e)	# TODO: REMOVE DEBUG, or make it use logging
			self.set_done()
			# unschedule all, we don't know how many have been produced actually
			# but only if we don't apply single please 
			if not self.apply_single:
				self._slock.acquire()
				self._scheduled_items -= len(items)
				self._slock.release()
			# END unschedule all
		# END exception handling
		del(wc)
		
		# if we didn't get all demanded items, which is also the case if count is 0
		# we have depleted the input channel and are done
		# We could check our output channel for how many items we have and put that 
		# into the equation, but whats important is that we were asked to produce
		# count items.
		if not items or len(items) != count:
			self.set_done()
		# END handle done state
		
		# If we appear to be the only one left with our output channel, and are 
		# closed ( this could have been set in another thread as well ), make 
		# sure to close the output channel.
		# The count is: 1 = wc itself, 2 = first reader channel, + x for every 
		# thread having its copy on the stack 
		# + 1 for the instance we provide to refcount
		if self.is_done() and sys.getrefcount(self._out_wc) < 4:
			self.close()
		# END handle channel closure
	#{ Configuration


class ThreadTaskBase(object):
	"""Describes tasks which can be used with theaded pools"""
	pass


class InputIteratorTaskBase(OutputChannelTask):
	"""Implements a task which processes items from an iterable in a multi-processing 
	safe manner"""
	__slots__ = ('_iterator', '_lock')
	# the type of the lock to use when reading from the iterator
	lock_type = None
	
	def __init__(self, iterator, *args, **kwargs):
		OutputChannelTask.__init__(self, *args, **kwargs)
		if not hasattr(iterator, 'next'):
			raise ValueError("Iterator %r needs a next() function" % iterator)
		self._iterator = iterator
		self._lock = self.lock_type()
		self._read = self.__read
		
	def __read(self, count=0):
		"""Read count items from the iterator, and return them"""
		self._lock.acquire()
		try:
			if count == 0:
				return list(self._iterator)
			else:
				out = list()
				it = self._iterator
				for i in xrange(count):
					try:
						out.append(it.next())
					except StopIteration:
						break
					# END handle empty iterator
				# END for each item to take
				return out
			# END handle count
		finally:
			self._lock.release()
		# END handle locking
		
		
class InputIteratorThreadTask(InputIteratorTaskBase, ThreadTaskBase):
	"""An input iterator for threaded pools"""
	lock_type = threading.Lock
		

class InputChannelTask(OutputChannelTask):
	"""Uses an input channel as source for reading items
	For instantiation, it takes all arguments of its base, the first one needs
	to be the input channel to read from though."""
	__slots__ = (
					'in_rc',			# channel to read items from  
					'_pool_ref'			# to be set by Pool
				)
	
	def __init__(self, in_rc, *args, **kwargs):
		OutputChannelTask.__init__(self, *args, **kwargs)
		self._in_rc = in_rc
		
	def process(self, count=1):
		"""Verify our setup, and do some additional checking, before the 
		base implementation can permanently perform all operations"""
		self._read = self._in_rc.read
		# make sure we don't trigger the pool if we read from a pool channel which 
		# belongs to our own pool. Channels from different pools are fine though, 
		# there we want to trigger its computation
		# PROBLEM: if the user keeps an end, but decides to put the same end into
		# a task of this pool, then all items might deplete without new ones being 
		# produced, causing a deadlock. Just triggering the pool would be better, 
		# but cost's more, unnecessarily if there is just one consumer, which is 
		# the user.
		# * could encode usage in the channel type, and fail if the refcount on 
		#   the read-pool channel is too high
		# * maybe keep track of the elements that are requested or in-production 
		#  for each task, which would allow to precisely determine whether 
		#  the pool as to be triggered, and bail out early. Problem would 
		#	be the 
		# * Perhaps one shouldn't seek the perfect solution , but instead
		#  document whats working and what not, or under which conditions.
		#  The whole system is simple, but gets more complicated the
		#  smarter it wants to be.
		if isinstance(self._in_rc, RPoolChannel) and self._in_rc._pool is self._pool_ref():
			self._read = self._in_rc._read
		
		# permanently install our base for processing
		self.process = new.instancemethod(OutputChannelTask.__dict__['process'], self, type(self))
		
		# and call it 
		return OutputChannelTask.process(self, count)
		
	def set_pool(self, pool):
		"""Set our pool to the given one, it will be weakref'd"""
		self._pool_ref = weakref.ref(pool)
	#{ Configuration
	
