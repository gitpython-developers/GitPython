from graph import Node
import threading
import new

class OutputChannelTask(Node):
	"""Abstracts a named task as part of a set of interdependent tasks, which contains 
	additional information on how the task should be queued and processed.
	
	Results of the item processing are sent to an output channel, which is to be 
	set by the creator"""
	__slots__ = (	'_read',			# method to yield items to process 
					'_out_wc', 			# output write channel
					'_exc',				# exception caught
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
		self.fun = fun
		self.min_count = None
		self.max_chunksize = 0				# note set
		self.apply_single = apply_single
	
	def is_done(self):
		""":return: True if we are finished processing"""
		return self._out_wc.closed
		
	def set_done(self):
		"""Set ourselves to being done, has we have completed the processing"""
		self._out_wc.close()
		
	def error(self):
		""":return: Exception caught during last processing or None"""
		return self._exc

	def process(self, count=0):
		"""Process count items and send the result individually to the output channel"""
		items = self._read(count)
		
		try:
			if self.apply_single:
				for item in items:
					self._out_wc.write(self.fun(item))
				# END for each item
			else:
				self._out_wc.write(self.fun(items))
			# END handle single apply
		except Exception, e:
			self._exc = e
			self.set_done()
		# END exception handling
		
		# if we didn't get all demanded items, which is also the case if count is 0
		# we have depleted the input channel and are done
		if len(items) != count:
			self.set_done()
		# END handle done state
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
		if isinstance(self._in_rc, RPoolChannel) and self._in_rc._pool is self._pool_ref():
			self._read = self._in_rc._read
		
		# permanently install our base for processing
		self.process = new.instancemethod(OutputChannelTask.__dict__['process'], self, type(self))
		
		# and call it 
		return OutputChannelTask.process(self, count)
	#{ Configuration
	
