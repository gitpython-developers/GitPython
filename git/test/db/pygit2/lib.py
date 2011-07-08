"""pygit2 specific utilities, as well as all the default ones"""

from git.test.lib import (
							InheritedTestMethodsOverrideWrapperMetaClsAutoMixin,
							needs_module_or_skip
						)

__all__ = ['needs_pygit2_or_skip', 'Pygit2RequiredMetaMixin']

#{ Decoorators

def needs_pygit2_or_skip(func):
	"""Skip this test if we have no pygit2 - print warning"""
	return needs_module_or_skip('pygit2')(func)

#}END decorators

#{ MetaClasses

class Pygit2RequiredMetaMixin(InheritedTestMethodsOverrideWrapperMetaClsAutoMixin):
	decorator = [needs_pygit2_or_skip]

#} END metaclasses
