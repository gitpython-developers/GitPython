"""Module with many useful complex databases with different useful combinations of primary implementations"""

from py.complex import PureGitDB
from cmd.complex import CmdPartialGitDB
from compat import RepoCompatibilityInterface

__all__ = ['CmdPartialGitDB', 'PureGitDB', 'PureCmdGitDB']

class PureCmdGitDB(PureGitDB, CmdPartialGitDB, RepoCompatibilityInterface):
	"""Repository which uses the pure implementation primarily, but falls back
	to the git command implementation. Please note that the CmdGitDB does it
	the opposite way around."""
