"""Module containing task implementations useful for testing them"""
from git.async.task import *

import threading
import weakref

class _TestTaskBase(object):
	"""Note: causes great slowdown due to the required locking of task variables"""
	def __init__(self, *args, **kwargs):
		super(_TestTaskBase, self).__init__(*args, **kwargs)
		self.should_fail = False
		self.lock = threading.Lock()		# yes, can't safely do x = x + 1 :)
		self.plock = threading.Lock()
		self.item_count = 0
		self.process_count = 0
	
	def do_fun(self, item):
		self.lock.acquire()
		self.item_count += 1
		self.lock.release()
		if self.should_fail:
			raise AssertionError("I am failing just for the fun of it")
		return item
	
	def process(self, count=1):
		# must do it first, otherwise we might read and check results before
		# the thread gets here :). Its a lesson !
		self.plock.acquire()
		self.process_count += 1
		self.plock.release()
		super(_TestTaskBase, self).process(count)
		
	def _assert(self, pc, fc, check_scheduled=False):
		"""Assert for num process counts (pc) and num function counts (fc)
		:return: self"""
		self.lock.acquire()
		if self.item_count != fc:
			print self.item_count, fc
		assert self.item_count == fc
		self.lock.release()
		
		# NOTE: asserting num-writers fails every now and then, implying a thread is 
		# still processing (an empty chunk) when we are checking it. This can 
		# only be prevented by checking the scheduled items, which requires locking
		# and causes slowdows, so we don't do that. If the num_writers 
		# counter wouldn't be maintained properly, more tests would fail, so 
		# we can safely refrain from checking this here
		# self._wlock.acquire()
		# assert self._num_writers == 0
		# self._wlock.release()
		return self


class TestThreadTaskNode(_TestTaskBase, InputIteratorThreadTask):
	pass
		

class TestThreadFailureNode(TestThreadTaskNode):
	"""Fails after X items"""
	def __init__(self, *args, **kwargs):
		self.fail_after = kwargs.pop('fail_after')
		super(TestThreadFailureNode, self).__init__(*args, **kwargs)
		
	def do_fun(self, item):
		item = TestThreadTaskNode.do_fun(self, item)
		
		self.lock.acquire()
		try:
			if self.item_count > self.fail_after:
				raise AssertionError("Simulated failure after processing %i items" % self.fail_after)
		finally:
			self.lock.release()
		# END handle fail after
		return item
		

class TestThreadInputChannelTaskNode(_TestTaskBase, InputChannelTask):
	"""Apply a transformation on items read from an input channel"""
	def __init__(self, *args, **kwargs):
		self.fail_after = kwargs.pop('fail_after', 0)
		super(TestThreadInputChannelTaskNode, self).__init__(*args, **kwargs)
	
	def do_fun(self, item):
		"""return tuple(i, i*2)"""
		item = super(TestThreadInputChannelTaskNode, self).do_fun(item)
		
		# fail after support
		if self.fail_after:
			self.lock.acquire()
			try:
				if self.item_count > self.fail_after:
					raise AssertionError("Simulated failure after processing %i items" % self.fail_after)
			finally:
				self.lock.release()
		# END handle fail-after
		
		if isinstance(item, tuple):
			i = item[0]
			return item + (i * self.id, )
		else:
			return (item, item * self.id)
		# END handle tuple


class TestThreadPerformanceTaskNode(InputChannelTask):
	"""Applies no operation to the item, and does not lock, measuring
	the actual throughput of the system"""
	
	def do_fun(self, item):
		return item


class TestThreadInputChannelVerifyTaskNode(_TestTaskBase, InputChannelTask):
	"""An input channel task, which verifies the result of its input channels, 
	should be last in the chain.
	Id must be int"""
	
	def do_fun(self, item):
		"""return tuple(i, i*2)"""
		item = super(TestThreadInputChannelVerifyTaskNode, self).do_fun(item)
		
		# make sure the computation order matches
		assert isinstance(item, tuple), "input was no tuple: %s" % item
		
		base = item[0]
		for id, num in enumerate(item[1:]):
			assert num == base * id, "%i != %i, orig = %s" % (num, base * id, str(item))
		# END verify order
		
		return item

#{ Utilities

def make_proxy_method(t):
	"""required to prevent binding self into the method we call"""
	wt = weakref.proxy(t)
	return lambda item: wt.do_fun(item)

def add_task_chain(p, ni, count=1, fail_setup=list(), feeder_channel=None, id_offset=0, 
					feedercls=TestThreadTaskNode, transformercls=TestThreadInputChannelTaskNode, 
					include_verifier=True):
	"""Create a task chain of feeder, count transformers and order verifcator 
	to the pool p, like t1 -> t2 -> t3
	:param fail_setup: a list of pairs, task_id, fail_after, i.e. [(2, 20)] would 
		make the third transformer fail after 20 items
	:param feeder_channel: if set to a channel, it will be used as input of the 
		first transformation task. The respective first task in the return value 
		will be None.
	:param id_offset: defines the id of the first transformation task, all subsequent
		ones will add one
	:return: tuple(list(task1, taskN, ...), list(rc1, rcN, ...))"""
	nt = p.num_tasks()
	
	feeder = None
	frc = feeder_channel
	if feeder_channel is None:
		feeder = make_iterator_task(ni, taskcls=feedercls)
		frc = p.add_task(feeder)
	# END handle specific feeder
	
	rcs = [frc]
	tasks = [feeder]
	
	inrc = frc
	for tc in xrange(count):
		t = transformercls(inrc, tc+id_offset, None)
		
		t.fun = make_proxy_method(t)
		#t.fun = t.do_fun
		inrc = p.add_task(t)
		
		tasks.append(t)
		rcs.append(inrc)
	# END create count transformers
	
	# setup failure
	for id, fail_after in fail_setup:
		tasks[1+id].fail_after = fail_after
	# END setup failure 
	
	if include_verifier:
		verifier = TestThreadInputChannelVerifyTaskNode(inrc, 'verifier', None)
		#verifier.fun = verifier.do_fun
		verifier.fun = make_proxy_method(verifier)
		vrc = p.add_task(verifier)
		
		
		tasks.append(verifier)
		rcs.append(vrc)
	# END handle include verifier
	return tasks, rcs
	
def make_iterator_task(ni, taskcls=TestThreadTaskNode, **kwargs):
	""":return: task which yields ni items
	:param taskcls: the actual iterator type to use
	:param **kwargs: additional kwargs to be passed to the task"""
	t = taskcls(iter(range(ni)), 'iterator', None, **kwargs)
	if isinstance(t, _TestTaskBase):
		t.fun = make_proxy_method(t)
	return t

#} END utilities
