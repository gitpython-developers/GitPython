# -*- coding: utf-8 -*-
"""Module with threading utilities"""
__docformat__ = "restructuredtext"
import threading
import inspect
import Queue

import sys

#{ Decorators

def do_terminate_threads(whitelist=list()):
	"""Simple function which terminates all of our threads
	:param whitelist: If whitelist is given, only the given threads will be terminated"""
	for t in threading.enumerate():
		if not isinstance(t, TerminatableThread):
			continue
		if whitelist and t not in whitelist:
			continue
		t.stop_and_join()
	# END for each thread

def terminate_threads( func ):
	"""Kills all worker threads the method has created by sending the quit signal.
	This takes over in case of an error in the main function"""
	def wrapper(*args, **kwargs):
		cur_threads = set(threading.enumerate())
		try:
			return func(*args, **kwargs)
		finally:
			do_terminate_threads(set(threading.enumerate()) - cur_threads)
		# END finally shutdown threads
	# END wrapper 
	wrapper.__name__ = func.__name__
	return wrapper

#} END decorators

#{ Classes
	
class TerminatableThread(threading.Thread):
	"""A simple thread able to terminate itself on behalf of the user.
	
	Terminate a thread as follows:
	
	t.stop_and_join()
	
	Derived classes call _should_terminate() to determine whether they should 
	abort gracefully
	"""
	__slots__ = '_terminate'
	
	def __init__(self):
		super(TerminatableThread, self).__init__()
		self._terminate = False
		
		
	#{ Subclass Interface
	def _should_terminate(self):
		""":return: True if this thread should terminate its operation immediately"""
		return self._terminate
		
	def _terminated(self):
		"""Called once the thread terminated. Its called in the main thread
		and may perform cleanup operations"""
		pass

	def start(self):
		"""Start the thread and return self"""
		super(TerminatableThread, self).start()
		return self
	
	#} END subclass interface
		
	#{ Interface 
		
	def stop_and_join(self):
		"""Ask the thread to stop its operation and wait for it to terminate
		:note: Depending on the implenetation, this might block a moment"""
		self._terminate = True
		self.join()
		self._terminated()
	#} END interface
	
	
class StopProcessing(Exception):
	"""If thrown in a function processed by a WorkerThread, it will terminate"""
	

class WorkerThread(TerminatableThread):
	""" This base allows to call functions on class instances natively.
	As it is meant to work with a pool, the result of the call must be 
	handled by the callee.
	The thread runs forever unless it receives the terminate signal using 
	its task queue.
	
	Tasks could be anything, but should usually be class methods and arguments to
	allow the following:
	
	inq = Queue()
	w = WorkerThread(inq)
	w.start()
	inq.put((WorkerThread.<method>, args, kwargs))
	
	finally we call quit to terminate asap.
	
	alternatively, you can make a call more intuitively - the output is the output queue
	allowing you to get the result right away or later
	w.call(arg, kwarg='value').get()
	
	inq.put(WorkerThread.quit)
	w.join()
	
	You may provide the following tuples as task:
	t[0] = class method, function or instance method
	t[1] = optional, tuple or list of arguments to pass to the routine
	t[2] = optional, dictionary of keyword arguments to pass to the routine
	"""
	__slots__ = ('inq', '_current_routine')
	
	
	# define how often we should check for a shutdown request in case our 
	# taskqueue is empty
	shutdown_check_time_s = 0.5
	
	def __init__(self, inq = None):
		super(WorkerThread, self).__init__()
		self.inq = inq
		if inq is None:
			self.inq = Queue.Queue()
		self._current_routine = None				# routine we execute right now
	
	@classmethod
	def stop(cls, *args):
		"""If send via the inq of the thread, it will stop once it processed the function"""
		raise StopProcessing
	
	def run(self):
		"""Process input tasks until we receive the quit signal"""
		print self.name, "starts processing"	# DEBUG
		
		gettask = self.inq.get
		while True:
			self._current_routine = None
			if self._should_terminate():
				break
			# END check for stop request
			
			# we wait and block - to terminate, send the 'stop' method
			tasktuple = gettask()
			
			# needing exactly one function, and one arg
			assert len(tasktuple) == 2, "Need tuple of function, arg - it could be more flexible, but its reduced to what we need"
			routine, arg = tasktuple
			
			self._current_routine = routine
			
			try:
				rval = None
				if inspect.ismethod(routine):
					if routine.im_self is None:
						rval = routine(self, arg)
					else:
						rval = routine(arg)
				elif inspect.isroutine(routine):
					rval = routine(arg)
				else:
					# ignore unknown items
					print >> sys.stderr, "%s: task %s was not understood - terminating" % (self.getName(), str(tasktuple))
					break
				# END make routine call
			except StopProcessing:
				print self.name, "stops processing"	# DEBUG
				break
			except Exception,e:
				print >> sys.stderr, "%s: Task %s raised unhandled exception: %s - this really shouldn't happen !" % (self.getName(), str(tasktuple), str(e))
				continue	# just continue 
			# END routine exception handling
		# END endless loop
	
	def routine(self):
		""":return: routine we are currently executing, or None if we have no task"""
		return self._current_routine
	
	def stop_and_join(self):
		"""Send stop message to ourselves"""
		self.inq.put((self.stop, None))
		super(WorkerThread, self).stop_and_join()
#} END classes
