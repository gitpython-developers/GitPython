"""Module with utilities related to async operations"""

from threading import (
	Lock,
	_Condition, 
	_sleep,
	_time,
	)

from Queue import (
		Queue, 
		Empty,
		)

from collections import deque
import sys
import os

#{ Routines 

def cpu_count():
	""":return:number of CPUs in the system
	:note: inspired by multiprocessing"""
	num = 0
	try:
		if sys.platform == 'win32':
			num = int(os.environ['NUMBER_OF_PROCESSORS'])
		elif 'bsd' in sys.platform or sys.platform == 'darwin':
			num = int(os.popen('sysctl -n hw.ncpu').read())
		else:
			num = os.sysconf('SC_NPROCESSORS_ONLN')
	except (ValueError, KeyError, OSError, AttributeError):
		pass
	# END exception handling
	
	if num == 0:
		raise NotImplementedError('cannot determine number of cpus')
	
	return num
	
#} END routines


class SyncQueue(deque):
	"""Adapter to allow using a deque like a queue, without locking"""
	def get(self, block=True, timeout=None):
		try:
			return self.pop()
		except IndexError:
			raise Empty
		# END raise empty
			
	def empty(self):
		return len(self) == 0
		
	put = deque.append
	
	
class HSCondition(_Condition):
	"""An attempt to make conditions less blocking, which gains performance 
	in return by sleeping less"""
	delay = 0.0001		# reduces wait times, but increases overhead
	
	def wait(self, timeout=None):
		waiter = Lock()
		waiter.acquire()
		self.__dict__['_Condition__waiters'].append(waiter)
		saved_state = self._release_save()
		try:	# restore state no matter what (e.g., KeyboardInterrupt)
			if timeout is None:
				waiter.acquire()
			else:
				# Balancing act:  We can't afford a pure busy loop, so we
				# have to sleep; but if we sleep the whole timeout time,
				# we'll be unresponsive.  The scheme here sleeps very
				# little at first, longer as time goes on, but never longer
				# than 20 times per second (or the timeout time remaining).
				endtime = _time() + timeout
				delay = self.delay
				acquire = waiter.acquire
				while True:
					gotit = acquire(0)
					if gotit:
						break
					remaining = endtime - _time()
					if remaining <= 0:
						break
					# this makes 4 threads working as good as two, but of course
					# it causes more frequent micro-sleeping
					#delay = min(delay * 2, remaining, .05)
					_sleep(delay)
				# END endless loop
				if not gotit:
					try:
						self.__dict__['_Condition__waiters'].remove(waiter)
					except ValueError:
						pass
				# END didn't ever get it
		finally:
			self._acquire_restore(saved_state)
			
	def notify(self, n=1):
		__waiters = self.__dict__['_Condition__waiters']
		if not __waiters:
			return
		if n == 1:
			__waiters[0].release()
			try:
				__waiters.pop(0)
			except IndexError:
				pass
		else:
			waiters = __waiters[:n]
			for waiter in waiters:
				waiter.release()
				try:
					__waiters.remove(waiter)
				except ValueError:
					pass
		# END handle n = 1 case faster
	
class AsyncQueue(Queue):
	"""A queue using different condition objects to gain multithreading performance"""
	def __init__(self, maxsize=0):
		Queue.__init__(self, maxsize)
		
		self.not_empty = HSCondition(self.mutex)
		self.not_full = HSCondition(self.mutex)
		self.all_tasks_done = HSCondition(self.mutex)
		
	
#} END utilities
