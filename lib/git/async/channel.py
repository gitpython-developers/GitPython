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
	__slots__ = ('_queue')
	
	def __init__(self):
		"""initialize this instance, able to hold max_items at once
		Write calls will block if the channel is full, until someone reads from it"""
		self._queue = AsyncQueue()
		
	
	#{ Interface 
	def write(self, item, block=True, timeout=None):
		"""Send an item into the channel, it can be read from the read end of the 
		channel accordingly
		:param item: Item to send
		:param block: If True, the call will block until there is free space in the 
			channel
		:param timeout: timeout in seconds for blocking calls.
		:raise ReadOnly: when writing into closed channel"""
		# let the queue handle the 'closed' attribute, we write much more often 
		# to an open channel than to a closed one, saving a few cycles
		self._queue.put(item, block, timeout)
		
	def size(self):
		""":return: approximate number of items that could be read from the read-ends
			of this channel"""
		return self._queue.qsize()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		self._queue.set_writable(False)
		
	def closed(self):
		""":return: True if the channel was closed"""
		return not self._queue.writable()
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
			The timeout is applied to each read item, not for the whole operation.
		:return: single item in a list if count is 1, or a list of count items. 
			If the channel was empty and count was 1, an empty list will be returned.
			If count was greater 1, a list with less than count items will be 
			returned.
			If count was < 1, a list with all items that could be read will be 
			returned."""
		# if the channel is closed for writing, we never block
		# NOTE: is handled by the queue
		# We don't check for a closed state here has it costs time - most of 
		# the time, it will not be closed, and will bail out automatically once
		# it gets closed
		
		
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
			
			i = 0
			while i < count:
				try:
					out.append(queue.get(block, timeout))
					i += 1
				except Empty:
					# here we are only if 
					# someone woke us up to inform us about the queue that changed
					# its writable state
					# The following branch checks for closed channels, and pulls
					# as many items as we need and as possible, before 
					# leaving the loop.
					if not queue.writable():
						try:
							while i < count:
								out.append(queue.get(False, None))
								i += 1
							# END count loop
						except Empty:
							break	# out of count loop 
						# END handle absolutely empty queue
					# END handle closed channel 
					
					# if we are here, we woke up and the channel is not closed
					# Either the queue became writable again, which currently shouldn't
					# be able to happen in the channel, or someone read with a timeout
					# that actually timed out.
					# As it timed out, which is the only reason we are here, 
					# we have to abort
					break
				# END ignore empty
				
			# END for each item
		# END handle blocking
		return out
		
	#} END interface 
	
#} END classes
