# -*- coding: utf-8 -*-
"""Module with threading utilities"""
__docformat__ = "restructuredtext"
import threading
import inspect
import Queue

import sys

__all__ = ('do_terminate_threads', 'terminate_threads', 'TerminatableThread', 
			'WorkerThread') 
		

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
	__slots__ = ('inq')
	
	
	# define how often we should check for a shutdown request in case our 
	# taskqueue is empty
	shutdown_check_time_s = 0.5
	
	def __init__(self, inq = None):
		super(WorkerThread, self).__init__()
		self.inq = inq
		if inq is None:
			self.inq = Queue.Queue()
	
	@classmethod
	def stop(cls, *args):
		"""If send via the inq of the thread, it will stop once it processed the function"""
		raise StopProcessing
	
	def run(self):
		"""Process input tasks until we receive the quit signal"""
		gettask = self.inq.get
		while True:
			if self._should_terminate():
				break
			# END check for stop request
			
			# note: during shutdown, this turns None in the middle of waiting 
			# for an item to be put onto it - we can't du anything about it - 
			# even if we catch everything and break gracefully, the parent 
			# call will think we failed with an empty exception.
			# Hence we just don't do anything about it. Alternatively
			# we could override the start method to get our own bootstrapping, 
			# which would mean repeating plenty of code in of the threading module.
			tasktuple = gettask()
				
			# needing exactly one function, and one arg
			routine, arg = tasktuple
			
			try:
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
						sys.stderr.write("%s: task %s was not understood - terminating\n" % (self.getName(), str(tasktuple)))
						break
					# END make routine call
				finally:
					# make sure we delete the routine to release the reference as soon
					# as possible. Otherwise objects might not be destroyed 
					# while we are waiting
					del(routine)
					del(tasktuple)
			except StopProcessing:
				break
			except Exception,e:
				sys.stderr.write("%s: Task %s raised unhandled exception: %s - this really shouldn't happen !\n" % (self.getName(), str(tasktuple), str(e)))
				continue	# just continue 
			# END routine exception handling
		
			# END handle routine release
		# END endless loop
	
	def stop_and_join(self):
		"""Send stop message to ourselves - we don't block, the thread will terminate 
		once it has finished processing its input queue to receive our termination
		event"""
		# DONT call superclass as it will try to join - join's don't work for 
		# some reason, as python apparently doesn't switch threads (so often)
		# while waiting ... I don't know, but the threads respond properly, 
		# but only if dear python switches to them
		self.inq.put((self.stop, None))
#} END classes
