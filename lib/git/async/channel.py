"""Contains a queue based channel implementation"""
from Queue import (
	Empty, 
	Full
	)

from util import AsyncQueue
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
			max_items = 0
			if len(args) == 1:
				max_items = args[0]
			if len(args) > 1:
				raise ValueError("Specify not more than the number of items the channel should take")
			wc = WChannel(max_items)
			rc = RChannel(wc)
			return wc, rc
		# END constructor mode
		return object.__new__(cls)


class WChannel(Channel):
	"""The write end of a channel"""
	__slots__ = ('_closed', '_queue')
	
	def __init__(self, max_items=0):
		"""initialize this instance, able to hold max_items at once
		Write calls will block if the channel is full, until someone reads from it"""
		self._closed = False
		self._queue = AsyncQueue(max_items)
		
	
	#{ Interface 
	def write(self, item, block=True, timeout=None):
		"""Send an item into the channel, it can be read from the read end of the 
		channel accordingly
		:param item: Item to send
		:param block: If True, the call will block until there is free space in the 
			channel
		:param timeout: timeout in seconds for blocking calls.
		:raise IOError: when writing into closed file
		:raise EOFError: when writing into a non-blocking full channel
		:note: may block if the channel has a limited capacity"""
		if self._closed:
			raise IOError("Cannot write to a closed channel")
			
		try:
			self._queue.put(item, block, timeout)
		except Full:
			raise EOFError("Capacity of the channel was exeeded")
		# END exception handling
		
	def size(self):
		""":return: approximate number of items that could be read from the read-ends
			of this channel"""
		return self._queue.qsize()
		
	def close(self):
		"""Close the channel. Multiple close calls on a closed channel are no 
		an error"""
		self._closed = True
		
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
			given amount of seconds.
		:return: single item in a list if count is 1, or a list of count items. 
			If the channel was empty and count was 1, an empty list will be returned.
			If count was greater 1, a list with less than count items will be 
			returned.
			If count was < 1, a list with all items that could be read will be 
			returned."""
		# if the channel is closed for writing, we never block
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
			# if we have really bad timing, the source of the channel
			# marks itself closed, but before setting it, the thread 
			# switches to us. We read it, read False, and try to fetch
			# something, and never return. The whole closed channel thing
			# is not atomic ( of course )
			# This is why we never block for long, to get a chance to recheck
			# for closed channels.
			# We blend this into the timeout of the user
			ourtimeout = 0.25				# the smaller, the more responsive, but the slower 
			wc = self._wc
			timeout = (timeout is None and sys.maxint) or timeout		# make sure we can compute with it
			assert timeout != 0.0, "shouldn't block if timeout is 0"	# okay safe 
			if timeout and ourtimeout > timeout:
				ourtimeout = timeout
			# END setup timeout
			
			# to get everything into one loop, we set the count accordingly
			if count == 0:
				count = sys.maxint
			# END handle count
			
			for i in xrange(count):
				have_timeout = False
				st = time()
				while True:
					try:
						if wc.closed:
							have_timeout = True
							# its about the 'in the meanwhile' :) - get everything
							# we can in non-blocking mode. This will raise
							try:
								while True:
									out.append(queue.get(False))
								# END until it raises Empty
							except Empty:
								break
							# END finally, out of here
						# END don't continue on closed channels
						
						# END abort reading if it was closed ( in the meanwhile )
						out.append(queue.get(block, ourtimeout))
						break	# breakout right away
					except Empty:
						if timeout - (time() - st) <= 0:
							# hitting timeout
							have_timeout = True
							break
						# END abort if the user wants no more time spent here
					# END handle timeout
				# END endless timer loop
				if have_timeout:
					break
				# END stop on timeout
			# END for each item
		# END handle blocking
		return out
		
	#} END interface 
	
#} END classes
