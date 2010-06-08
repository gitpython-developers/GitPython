"""Contains a queue based channel implementation"""
from Queue import (
	Empty, 
	Full
	)

from util import (
		AsyncQueue, 
		ReadOnly
		)

from time import time
import sys

#{ Classes 
class Channel(object):
	"""A channel is similar to a file like object. It has a write end as well as one or
	more read ends. If Data is in the channel, it can be read, if not the read operation
	will block until data becomes available.
	If the channel is closed, any read operation will result in an exception
	
	This base class is not instantiated directly, but instead serves as constructor
	for RWChannel pairs.
	
	Create a new channel """
	__slots__ = tuple()
	
	def __new__(cls, *args):
		if cls is Channel:
			if len(args) > 0:
				raise ValueError("Cannot take any arguments when creating a new channel")
			wc = WChannel()
			rc = RChannel(wc)
			return wc, rc
		# END constructor mode
		return object.__new__(cls)


class WChannel(Channel):
	"""The write end of a channel"""
	__slots__ = ('_closed', '_queue')
	
	def __init__(self):
		"""initialize this instance, able to hold max_items at once
		Write calls will block if the channel is full, until someone reads from it"""
		self._closed = False
		self._queue = AsyncQueue()
		
	
	#{ Interface 
	def write(self, item, block=True, timeout=None):
		"""Send an item into the channel, it can be read from the read end of the 
		channel accordingly
		:param item: Item to send
		:param block: If True, the call will block until there is free space in the 
			channel
		:param timeout: timeout in seconds for blocking calls.
		:raise IOError: when writing into closed file
		:raise EOFError: when writing into a non-blocking full channel"""
		# let the queue handle the 'closed' attribute, we write much more often 
		# to an open channel than to a closed one, saving a few cycles
		try:
			self._queue.put(item, block, timeout)
		except ReadOnly:
			raise IOError("Cannot write to a closed channel")
		# END exception handling
		
	def size(self):
		""":return: approximate number of items that could be read from the read-ends
			of this channel"""
		return self._queue.qsize()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		# yes, close it a little too early, better than having anyone put 
		# additional items
		# print "closing channel", self
		self._closed = True
		self._queue.set_writable(False)
		
	@property
	def closed(self):
		""":return: True if the channel was closed"""
		return self._closed
	#} END interface 
	

class RChannel(Channel):
	"""The read-end of a corresponding write channel"""
	__slots__ = '_wc'
	
	def __init__(self, wchannel):
		"""Initialize this instance from its parent write channel"""
		self._wc = wchannel
		
		
	#{ Interface
	
	def read(self, count=0, block=True, timeout=None):
		"""read a list of items read from the channel. The list, as a sequence
		of items, is similar to the string of characters returned when reading from 
		file like objects.
		:param count: given amount of items to read. If < 1, all items will be read
		:param block: if True, the call will block until an item is available
		:param timeout: if positive and block is True, it will block only for the 
			given amount of seconds, returning the items it received so far.
		:return: single item in a list if count is 1, or a list of count items. 
			If the channel was empty and count was 1, an empty list will be returned.
			If count was greater 1, a list with less than count items will be 
			returned.
			If count was < 1, a list with all items that could be read will be 
			returned."""
		# if the channel is closed for writing, we never block
		# NOTE: is handled by the queue
		if self._wc.closed or timeout == 0:
			block = False
			
		# in non-blocking mode, its all not a problem
		out = list()
		queue = self._wc._queue
		if not block:
			# be as fast as possible in non-blocking mode, hence
			# its a bit 'unrolled'
			try:
				if count == 1:
					out.append(queue.get(False))
				elif count < 1:
					while True:
						out.append(queue.get(False))
					# END for each item
				else:
					for i in xrange(count):
						out.append(queue.get(False))
					# END for each item
				# END handle count
			except Empty:
				pass
			# END handle exceptions
		else:
			# to get everything into one loop, we set the count accordingly
			if count == 0:
				count = sys.maxint
			# END handle count
			
			endtime = sys.maxint		# allows timeout for whole operation
			if timeout is not None:
				endtime = time() + timeout
			# could be improved by a separate: no-endtime branch, saving the time calls
			for i in xrange(count):
				try:
					out.append(queue.get(block, timeout))
				except Empty:
					# here we are only if there is nothing on the queue, 
					# and if we are blocking. If we are not blocking, this 
					# indiccates that the queue was set unwritable in the meanwhile.
					# hence we can abort now to prevent reading (possibly) forever
					# Besides, this is racy as all threads will rip on the channel
					# without waiting until its empty
					if not block:
						break
				# END ignore empty
				
				# if we have been unblocked because the closed state changed 
				# in the meanwhile, stop trying
				# NOTE: must NOT cache _wc
				if self._wc.closed:
					# If we were closed, we drop out even if there might still 
					# be items. Now its time to get these items, according to 
					# our count. Just switch to unblocking mode.
					# If we are to read unlimited items, this would run forever, 
					# but the EmptyException handler takes care of this
					block = False
					
					# we don't continue, but let the timer decide whether
					# it wants to abort
				# END handle channel cloased
				
				if time() >= endtime:
					break
				# END stop operation on timeout
			# END for each item
		# END handle blocking
		return out
		
	#} END interface 
	
#} END classes
