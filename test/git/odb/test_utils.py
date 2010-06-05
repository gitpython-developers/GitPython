"""Test for object db"""
from test.testlib import *
from git import Blob
from git.odb.utils import (
	to_hex_sha, 
	to_bin_sha
	)

	
class TestUtils(TestBase):
	def test_basics(self):
		assert to_hex_sha(Blob.NULL_HEX_SHA) == Blob.NULL_HEX_SHA
		assert len(to_bin_sha(Blob.NULL_HEX_SHA)) == 20
		assert to_hex_sha(to_bin_sha(Blob.NULL_HEX_SHA)) == Blob.NULL_HEX_SHA

