"""Channel testing"""
from test.testlib import *
from git.async.pool import *
from git.async.task import *
from git.async.util import cpu_count

import time

class TestThreadTaskNode(InputIteratorThreadTask):
	def __init__(self, *args, **kwargs):
		super(TestThreadTaskNode, self).__init__(*args, **kwargs)
		self.reset()
	
	def do_fun(self, item):
		self.item_count += 1
		return item
	
	def reset(self):
		self.process_count = 0
		self.item_count = 0
		
	def process(self, count=1):
		super(TestThreadTaskNode, self).process(count)
		self.process_count += 1
		
	def _assert(self, pc, fc):
		"""Assert for num process counts (pc) and num function counts (fc)
		:return: self"""
		assert self.process_count == pc
		assert self.item_count == fc
		
		return self
		

class TestThreadPool(TestBase):
	
	max_threads = cpu_count()
	
	def test_base(self):
		p = ThreadPool()
		
		# default pools have no workers
		assert p.size() == 0
		
		# increase and decrease the size
		for i in range(self.max_threads):
			p.set_size(i)
			assert p.size() == i
		for i in range(self.max_threads, -1, -1):
			p.set_size(i)
			assert p.size() == i
			
		# currently in serial mode !
		
		# add a simple task
		# it iterates n items
		ni = 20
		task = TestThreadTaskNode(iter(range(ni)), 'iterator', None)
		task.fun = task.do_fun
		
		assert p.num_tasks() == 0
		rc = p.add_task(task)
		assert p.num_tasks() == 1
		assert isinstance(rc, RPoolChannel)
		assert task._out_wc is not None
		
		# pull the result completely - we should get one task, which calls its 
		# function once. In serial mode, the order matches
		items = rc.read()
		task._assert(1, ni).reset()
		assert len(items) == ni
		assert items[0] == 0 and items[-1] == ni-1
		
		
		# switch to threaded mode - just one thread for now
		
		# two threads to compete for tasks
		
	
