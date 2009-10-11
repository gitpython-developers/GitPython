# test_base.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import time
from test.testlib import *
from git import *

class TestBase(object):
	
	type_tuples = (  ("blob", "8741fc1d09d61f02ffd8cded15ff603eff1ec070"), 
					 ("tree", "3a6a5e3eeed3723c09f1ef0399f81ed6b8d82e79"),
					 ("commit", "4251bd59fb8e11e40c40548cba38180a9536118c") ) 
	
	def setup(self):
		self.repo = Repo(GIT_REPO)
		
	def test_base(self):	
		# test interface of base classes
		fcreators = (self.repo.blob, self.repo.tree, self.repo.commit )
		assert len(fcreators) == len(self.type_tuples)
		for fcreator, (typename, hexsha) in zip(fcreators, self.type_tuples):  
			item = fcreator(hexsha)
			assert item.id == hexsha
			assert item.type == typename
			assert item.size
		# END for each object type to create
		
		assert False,"TODO: Test for all types" 
		
	def test_tags(self):
		# tag refs can point to tag objects or to commits
		assert False, "TODO: Tag handling"

