# Copyright (C) 2010, 2011 Sebastian Thiel (byronimo@gmail.com) and contributors
#
# This module is part of GitDB and is released under
# the New BSD License: http://www.opensource.org/licenses/bsd-license.php
"""This module's whole purpose is to verify the __all__ descriptions in the respective
module, by importing using from x import *"""

# perform the actual imports
import os

from git import *

def import_all(topdir, topmodule='git', skip = "test"):
	base = os.path.basename
	join = os.path.join
	init_script = '__init__.py'
	prev_cwd = os.getcwd()
	try:
		os.chdir(os.path.dirname(topdir))
		for root, dirs, files in os.walk(base(topdir)):
			if init_script not in files:
				del(dirs[:])
				continue
			#END ignore non-packages
			
			if skip in root:
				continue
			#END handle ignores
			
			for relafile in files:
				if not relafile.endswith('.py'):
					continue
				if relafile == init_script:
					continue
				module_path = join(root, os.path.splitext(relafile)[0]).replace("/", ".").replace("\\", ".")
				
				m = __import__(module_path, globals(), locals(), [""])
				try:
					attrlist = m.__all__
					for attr in attrlist:
						assert hasattr(m, attr), "Invalid item in %s.__all__: %s" % (module_path, attr) 
					#END veriy
				except AttributeError:
					pass
				# END try each listed attribute
			#END for each file in dir
		#END for each item
	finally:
		os.chdir(prev_cwd)
	#END handle previous currentdir
	
	

class TestDummy(object):
	def test_base(self):
		dn = os.path.dirname
		# NOTE: i don't think this is working, as the __all__ variable is not used in this case
		import_all(dn(dn(__file__)))
