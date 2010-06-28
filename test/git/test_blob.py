# test_blob.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from test.testlib import *
from git import *
from gitdb.util import hex_to_bin

class TestBlob(TestBase):
    
    def test_should_cache_data(self):
        bid = 'a802c139d4767c89dcad79d836d05f7004d39aac'
        blob = Blob(self.rorepo, hex_to_bin(bid))
        blob.data
        assert blob.data
        blob.size
        blob.size
        
    def test_mime_type_should_return_mime_type_for_known_types(self):
        blob = Blob(self.rorepo, **{'binsha': Blob.NULL_BIN_SHA, 'path': 'foo.png'})
        assert_equal("image/png", blob.mime_type)
  
    def test_mime_type_should_return_text_plain_for_unknown_types(self):
        blob = Blob(self.rorepo, **{'binsha': Blob.NULL_BIN_SHA,'path': 'something'})
        assert_equal("text/plain", blob.mime_type)
  
