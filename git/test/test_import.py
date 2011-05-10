# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""This module's whole purpose is to verify the __all__ descriptions in the respective
module, by importing using from x import *"""

# perform the actual imports

from nose import SkipTest

class TestDummy(object):
	def test_base(self):
		raise SkipTest("todo")
