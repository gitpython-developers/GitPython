"""Channel testing"""
from test.testlib import *
from git.async.task import *

import time

class TestTask(TestBase):
	
	max_threads = cpu_count()
	
	def test_iterator_task(self):
		self.fail("test iterator task")
