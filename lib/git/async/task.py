from graph import Node
from util import ReadOnly

import threading
import sys
import new

getrefcount = sys.getrefcount

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
		self._done = False		# TODO : fix this, this is a side-effect
		self._scheduled_items = 0
		self._out_wc = wc
		
	def close(self):
		"""A closed task will close its channel to assure the readers will wake up
		:note: its safe to call this method multiple times"""
		self._out_wc.close()
		
	def is_closed(self):
		""":return: True if the task's write channel is closed"""
		return self._out_wc.closed()
		
	def error(self):
		""":return: Exception caught during last processing or None"""
		return self._exc

	def process(self, count=0):
		"""Process count items and send the result individually to the output channel"""
		items = self._read(count)
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
					wc.write(rval)
				# END for each item
			else:
				# shouldn't apply single be the default anyway ? 
				# The task designers should chunk them up in advance
				rvals = self.fun(items)
				for rval in rvals:
					wc.write(rval)
			# END handle single apply
		except Exception, e:
			print >> sys.stderr, "task error:", str(e)	# TODO: REMOVE DEBUG, or make it use logging
			
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
		if self.is_done() and getrefcount(self._out_wc) < 4:
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
	
	def __init__(self, in_rc, *args, **kwargs):
		OutputChannelTask.__init__(self, *args, **kwargs)
		self._read = in_rc.read
	
	def process(self, count=1):
		# for now, just blindly read our input, could trigger a pool, even 
		# ours, but why not ? It should be able to handle this
		# TODO: remove this method
		super(InputChannelTask, self).process(count)
	#{ Configuration
	
