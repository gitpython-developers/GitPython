"""Module with our own git implementation - it uses the git command"""

from git.db.compat import RepoCompatInterface
from git.db.py.complex import PureGitDB

from base import *


__all__ = ['GitCmdDB', 'CmdCompatibilityGitDB']


class CmdGitDB(	GitCommandMixin, CmdObjectDBRMixin, CmdTransportMixin, 
				CmdHighLevelRepository, PureGitDB):
	pass

class CmdCompatibilityGitDB(CmdGitDB, RepoCompatInterface):
	"""Command git database with the compatabilty interface added for 0.3x code"""
