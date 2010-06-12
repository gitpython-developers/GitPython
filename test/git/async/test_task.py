"""Channel testing"""
from test.testlib import *
from git.async.util import *
from git.async.task import *

import time

class TestTask(TestBase):
	
	max_threads = cpu_count()
	
	def test_iterator_task(self):
		# tested via test_pool
		pass
		
