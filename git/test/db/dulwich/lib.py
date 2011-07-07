"""dulwich specific utilities, as well as all the default ones"""

from git.test.lib import *

#{ Decoorators

def needs_dulwich_or_skip(func):
	"""Skip this test if we have no dulwich - print warning"""
	return needs_module_or_skip('dulwich')(func)

#}END decorators

#{ MetaClasses

class DulwichRequiredMetaMixin(InheritedTestMethodsOverrideWrapperMetaClsAutoMixin):
	decorator = [needs_dulwich_or_skip]

#} END metaclasses
