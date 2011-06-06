"""Module with many useful complex databases with different useful combinations of primary implementations"""

from py.complex import PurePartialGitDB
from cmd.complex import CmdPartialGitDB
from compat import RepoCompatibilityInterface

__all__ = ['CmdGitDB', 'PureGitDB', 'CmdCompatibilityGitDB', 'PureCompatibilityGitDB']

class CmdGitDB(CmdPartialGitDB, PurePartialGitDB):
	"""A database which uses primarily the git command implementation, but falls back
	to pure python where it is more feasible
	:note: To assure consistent behaviour across implementations, when calling the 
		``stream()`` method a cache is created. This makes this implementation a bad
		choice when reading big files as these are streamed from memory in all cases."""

class CmdCompatibilityGitDB(RepoCompatibilityInterface, CmdGitDB):
	"""A database which fills in its missing implementation using the pure python 
	implementation"""
	pass

class PureGitDB(PurePartialGitDB, CmdPartialGitDB):
	"""A repository which uses the pure implementation primarily, but falls back
	on using the git command for high-level functionality"""

class PureCompatibilityGitDB(RepoCompatibilityInterface, PureGitDB):
	"""Repository which uses the pure implementation primarily, but falls back
	to the git command implementation. Please note that the CmdGitDB does it
	the opposite way around."""
