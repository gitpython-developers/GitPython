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
		
		# check num of sequence-acceses
		for cls in (list, tuple):
			x = 10
			st = time()
			s = cls(range(x))
			for i in xrange(ni):
				s[0]
				s[1]
				s[2]
			# END for
			elapsed = time() - st
			na = ni * 3
			print >> sys.stderr, "Accessed %s[x] %i times in %s s ( %f acc / s)" % (cls.__name__, na, elapsed, na / elapsed)
		# END for each sequence 
		
	def test_instantiation(self):
		ni = 100000
		max_num_items = 4
		for mni in range(max_num_items+1):
			for cls in (tuple, list):
				st = time()
				for i in xrange(ni):
					if mni == 0:
						cls()
					elif mni == 1:
						cls((1,))
					elif mni == 2:
						cls((1,2))
					elif mni == 3:
						cls((1,2,3))
					elif mni == 4:
						cls((1,2,3,4))
					else:
						cls(x for x in xrange(mni))
					# END handle empty cls
				# END for each item
				elapsed = time() - st
				print >> sys.stderr, "Created %i %ss of size %i in %f s ( %f inst / s)" % (ni, cls.__name__, mni, elapsed, ni / elapsed)
			# END for each type
		# END for each item count
		
		# tuple and tuple direct
		st = time()
		for i in xrange(ni):
			t = (1,2,3,4)
		# END for each item
		elapsed = time() - st
		print >> sys.stderr, "Created %i tuples (1,2,3,4) in %f s ( %f tuples / s)" % (ni, elapsed, ni / elapsed)
		
		st = time()
		for i in xrange(ni):
			t = tuple((1,2,3,4))
		# END for each item
		elapsed = time() - st
		print >> sys.stderr, "Created %i tuples tuple((1,2,3,4)) in %f s ( %f tuples / s)" % (ni, elapsed, ni / elapsed)
		
	def test_unpacking_vs_indexing(self):
		ni = 1000000
		list_items = [1,2,3,4]
		tuple_items = (1,2,3,4)
		
		for sequence in (list_items, tuple_items):
			st = time()
			for i in xrange(ni):
				one, two, three, four = sequence
			# END for eac iteration
			elapsed = time() - st
			print >> sys.stderr, "Unpacked %i %ss of size %i in %f s ( %f acc / s)" % (ni, type(sequence).__name__, len(sequence), elapsed, ni / elapsed)
			
			st = time()
			for i in xrange(ni):
				one, two, three, four = sequence[0], sequence[1], sequence[2], sequence[3]
			# END for eac iteration
			elapsed = time() - st
			print >> sys.stderr, "Unpacked %i %ss of size %i individually in %f s ( %f acc / s)" % (ni, type(sequence).__name__, len(sequence), elapsed, ni / elapsed)
			
			st = time()
			for i in xrange(ni):
				one, two = sequence[0], sequence[1]
			# END for eac iteration
			elapsed = time() - st
			print >> sys.stderr, "Unpacked %i %ss of size %i individually (2 of 4) in %f s ( %f acc / s)" % (ni, type(sequence).__name__, len(sequence), elapsed, ni / elapsed)
		# END for each sequence
		
	def test_large_list_vs_iteration(self):
		# what costs more: alloc/realloc of lists, or the cpu strain of iterators ?
		def slow_iter(ni):
			for i in xrange(ni):
				yield i
		# END slow iter - be closer to the real world
		
		# alloc doesn't play a role here it seems 
		for ni in (500, 1000, 10000, 20000, 40000):
			st = time()
			for i in list(xrange(ni)):
				i
			# END for each item
			elapsed = time() - st
			print >> sys.stderr, "Iterated %i items from list in %f s ( %f acc / s)" % (ni, elapsed, ni / elapsed)
			
			st = time()
			for i in slow_iter(ni):
				i
			# END for each item
			elapsed = time() - st
			print >> sys.stderr, "Iterated %i items from iterator in %f s ( %f acc / s)" % (ni, elapsed, ni / elapsed)
		# END for each number of iterations
		
	def test_type_vs_inst_class(self):
		class NewType(object):
			pass
		
		# lets see which way is faster
		inst = NewType()
		
		ni = 1000000
		st = time()
		for i in xrange(ni):
			inst.__class__()
		# END for each item
		elapsed = time() - st
		print >> sys.stderr, "Created %i items using inst.__class__ in %f s ( %f items / s)" % (ni, elapsed, ni / elapsed)
		
		st = time()
		for i in xrange(ni):
			type(inst)()
		# END for each item
		elapsed = time() - st
		print >> sys.stderr, "Created %i items using type(inst)() in %f s ( %f items / s)" % (ni, elapsed, ni / elapsed)
