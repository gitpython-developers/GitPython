# test_blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import time
from test.testlib import *
from git import *

class TestBlob(object):
	def setup(self):
		self.repo = Repo(GIT_REPO)
	
	def test_should_cache_data(self):
		bid = 'a802c139d4767c89dcad79d836d05f7004d39aac'
		blob = Blob(self.repo, bid)
		blob.data
		assert blob.data
		blob.size
		blob.size
		
	def test_mime_type_should_return_mime_type_for_known_types(self):
		blob = Blob(self.repo, **{'id': 'abc', 'path': 'foo.png'})
		assert_equal("image/png", blob.mime_type)
  
	def test_mime_type_should_return_text_plain_for_unknown_types(self):
		blob = Blob(self.repo, **{'id': 'abc','path': 'something'})
		assert_equal("text/plain", blob.mime_type)
  
	def test_should_return_appropriate_representation(self):
		blob = Blob(self.repo, **{'id': 'abc'})
		assert_equal('<git.Blob "abc">', repr(blob))
