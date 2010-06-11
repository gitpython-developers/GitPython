from graph import Node
from util import ReadOnly

import threading
import weakref
import sys
import new

class OutputChannelTask(Node):
	"""Abstracts a named task as part of a set of interdependent tasks, which contains 
	additional information on how the task should be queued and processed.
	
	Results of the item processing are sent to a write channel, which is to be 
	set by the creator using the ``set_writer`` method.
	
	* **min_count** assures that not less than min_count items will be processed per call.
	* **max_chunksize** assures that multi-threading is happening in smaller chunks. If 
	 someone wants all items to be processed, using read(0), the whole task would go to
	 one worker, as well as dependent tasks. If you want finer granularity , you can 
	 specify this here, causing chunks to be no larger than max_chunksize"""
	__slots__ = (	'_read',			# method to yield items to process 
					'_out_writer', 			# output write channel
					'_exc',				# exception caught
					'_done',			# True if we are done
					'_num_writers',		# number of concurrent writers
					'_wlock',			# lock for the above
					'fun',				# function to call with items read
					'min_count', 		# minimum amount of items to produce, None means no override
					'max_chunksize',	# maximium amount of items to process per process call
					'apply_single'		# apply single items even if multiple where read
					)
	
	def __init__(self, id, fun, apply_single=True, min_count=None, max_chunksize=0, 
					writer=None):
		Node.__init__(self, id)
		self._read = None					# to be set by subclasss 
		self._out_writer = writer
		self._exc = None
		self._done = False
		self._num_writers = 0
		self._wlock = threading.Lock()
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
		
	def set_writer(self, writer):
		"""Set the write channel to the given one"""
		self._out_writer = writer
		
	def writer(self):
		""":return: a proxy to our write channel or None if non is set
		:note: you must not hold a reference to our write channel when the 
			task is being processed. This would cause the write channel never 
			to be closed as the task will think there is still another instance
			being processed which can close the channel once it is done.
			In the worst case, this will block your reads."""
		if self._out_writer is None:
			return None
		return self._out_writer
		
	def close(self):
		"""A closed task will close its channel to assure the readers will wake up
		:note: its safe to call this method multiple times"""
		self._out_writer.close()
		
	def is_closed(self):
		""":return: True if the task's write channel is closed"""
		return self._out_writer.closed()
		
	def error(self):
		""":return: Exception caught during last processing or None"""
		return self._exc

	def process(self, count=0):
		"""Process count items and send the result individually to the output channel"""
		# first thing: increment the writer count - other tasks must be able 
		# to respond properly ( even if it turns out we don't need it later )
		self._wlock.acquire()
		self._num_writers += 1
		self._wlock.release()
		
		#print "%r: reading %i" % (self.id, count)
		#if hasattr(self, 'reader'):
		#	print "from", self.reader().channel
		items = self._read(count)
		#print "%r: done reading %i items" % (self.id, len(items))
		
		try:
			try:
				if items:
					write = self._out_writer.write
					if self.apply_single:
						for item in items:
							rval = self.fun(item)
							write(rval)
						# END for each item
					else:
						# shouldn't apply single be the default anyway ? 
						# The task designers should chunk them up in advance
						rvals = self.fun(items)
						for rval in rvals:
							write(rval)
					# END handle single apply
				# END if there is anything to do
			finally:
				self._wlock.acquire()
				self._num_writers -= 1
				self._wlock.release()
			# END handle writer count
		except Exception, e:
			print >> sys.stderr, "task %s error:" % self.id, type(e), str(e)	# TODO: REMOVE DEBUG, or make it use logging
			# be sure our task is not scheduled again
			self.set_done()
			
			# PROBLEM: We have failed to create at least one item, hence its not 
			# garantueed that enough items will be produced for a possibly blocking
			# client on the other end. This is why we have no other choice but
			# to close the channel, preventing the possibility of blocking.
			# This implies that dependent tasks will go down with us, but that is
			# just the right thing to do of course - one loose link in the chain ...
			# Other chunks of our kind currently being processed will then 
			# fail to write to the channel and fail as well
			self.close()
			
			# If some other chunk of our Task had an error, the channel will be closed
			# This is not an issue, just be sure we don't overwrite the original 
			# exception with the ReadOnly error that would be emitted in that case.
			# We imply that ReadOnly is exclusive to us, as it won't be an error
			# if the user emits it
			if not isinstance(e, ReadOnly):
				self._exc = e
			# END set error flag
		# END exception handling
		
		
		# if we didn't get all demanded items, which is also the case if count is 0
		# we have depleted the input channel and are done
		# We could check our output channel for how many items we have and put that 
		# into the equation, but whats important is that we were asked to produce
		# count items.
		if not items or len(items) != count:
			self.set_done()
		# END handle done state
		
		# If we appear to be the only one left with our output channel, and are 
		# done ( this could have been set in another thread as well ), make 
		# sure to close the output channel.
		# Waiting with this to be the last one helps to keep the 
		# write-channel writable longer
		# The count is: 1 = wc itself, 2 = first reader channel, + x for every 
		# thread having its copy on the stack 
		# + 1 for the instance we provide to refcount
		# Soft close, so others can continue writing their results
		if self.is_done():
			self._wlock.acquire()
			try:
				if self._num_writers == 0:
					# print "Closing channel of %r" % self.id, len(self._out_writer.channel.queue), self._out_writer.channel
					self.close()
				# END handle writers
			finally:
				self._wlock.release()
			# END assure lock release
		# END handle channel closure
	#{ Configuration


class ThreadTaskBase(object):
	"""Describes tasks which can be used with theaded pools"""
	pass


class InputIteratorTaskBase(OutputChannelTask):
	"""Implements a task which processes items from an iterable in a multi-processing 
	safe manner"""
	__slots__ = ('_iterator', '_lock', '_empty')
	# the type of the lock to use when reading from the iterator
	lock_type = None
	
	def __init__(self, iterator, *args, **kwargs):
		OutputChannelTask.__init__(self, *args, **kwargs)
		if not hasattr(iterator, 'next'):
			raise ValueError("Iterator %r needs a next() function" % iterator)
		self._iterator = iterator
		self._lock = self.lock_type()
		
		# this is necessary to prevent a cyclic ref, preventing us from 
		# getting deleted ( and collected )
		weakself = weakref.ref(self)
		self._read = lambda count: weakself().__read(count)
		self._empty = False
		
	def __read(self, count=0):
		"""Read count items from the iterator, and return them"""
		# not threadsafe, but worst thing that could happen is that 
		# we try to get items one more time
		if self._empty:
			return list()
		# END early abort
		
		self._lock.acquire()
		try:
			if count == 0:
				self._empty = True
				return list(self._iterator)
			else:
				out = list()
				it = self._iterator
				for i in xrange(count):
					try:
						out.append(it.next())
					except StopIteration:
						self._empty = True
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
		

class InputChannelTask(OutputChannelTask, ThreadTaskBase):
	"""Uses an input channel as source for reading items
	For instantiation, it takes all arguments of its base, the first one needs
	to be the input channel to read from though."""
	__slots__ = "_pool_ref"
	
	def __init__(self, in_reader, *args, **kwargs):
		OutputChannelTask.__init__(self, *args, **kwargs)
		self._read = in_reader.read
		self._pool_ref = None

	#{ Internal Interface 
	
	def reader(self):
		""":return: input channel from which we read"""
		# the instance is bound in its instance method - lets use this to keep
		# the refcount at one ( per consumer )
		return self._read.im_self
		
	def set_read(self, read):
		"""Adjust the read method to the given one"""
		self._read = read
		
	def set_pool(self, pool):
		self._pool_ref = weakref.ref(pool)
		
	def pool(self):
		""":return: pool we are attached to, or None"""
		if self._pool_ref is None:
			return None
		return self._pool_ref()
		
	#} END intenral interface
