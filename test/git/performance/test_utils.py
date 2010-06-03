"""Performance of utilities"""
from time import time
import sys
import stat

from lib import (
	TestBigRepoR
	)


class TestUtilPerformance(TestBigRepoR):
	
	def test_access(self):
		# compare dict vs. slot access
		class Slotty(object):
			__slots__ = "attr"
			def __init__(self):
				self.attr = 1
				
		class Dicty(object):
			def __init__(self):
				self.attr = 1
				
		class BigSlotty(object):
			__slots__ = ('attr', ) + tuple('abcdefghijk')
			def __init__(self):
				for attr in self.__slots__:
					setattr(self, attr, 1)
					
		class BigDicty(object):
			def __init__(self):
				for attr in BigSlotty.__slots__:
					setattr(self, attr, 1)
		
		ni = 1000000
		for cls in (Slotty, Dicty, BigSlotty, BigDicty):
			cli = cls()
			st = time()
			for i in xrange(ni):
				cli.attr
			# END for each access
			elapsed = time() - st
			print >> sys.stderr, "Accessed %s.attr %i times in %s s ( %f acc / s)" % (cls.__name__, ni, elapsed, ni / elapsed)
		# END for each class type
