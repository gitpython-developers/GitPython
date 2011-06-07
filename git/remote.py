# remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

# Module implementing a remote object allowing easy access to git remotes

from exc import GitCommandError
from ConfigParser import NoOptionError
from config import SectionConstraint

from git.util import (
						LazyMixin,
						Iterable,
						IterableList
						)
from git.db.interface import TransportDB
from refs import RemoteReference

import os

__all__ = ['Remote']

class PushInfo(object):
	"""Wrapper for basic PushInfo to provide the previous interface which includes
	resolved objects instead of plain shas
	
	old_commit	# object for the corresponding old_commit_sha"""
	
	
	
class FetchInfo(object):
	"""Wrapper to restore the previous interface, resolving objects and wrapping 
	references"""


class Remote(LazyMixin, Iterable):
	"""Provides easy read and write access to a git remote.
	
	Everything not part of this interface is considered an option for the current 
	remote, allowing constructs like remote.pushurl to query the pushurl.
	
	NOTE: When querying configuration, the configuration accessor will be cached
	to speed up subsequent accesses."""
	
	__slots__ = ( "repo", "name", "_config_reader" )
	_id_attribute_ = "name"
	
	def __init__(self, repo, name):
		"""Initialize a remote instance
		
		:param repo: The repository we are a remote of
		:param name: the name of the remote, i.e. 'origin'"""
		if not hasattr(repo, 'git'):
			# note: at some point we could just create a git command instance ourselves
			# but lets just be lazy for now
			raise AssertionError("Require repository to provide a git command instance currently")
		#END assert git cmd
		
		if not isinstance(repo, TransportDB):
			raise AssertionError("Require TransportDB interface implementation")
		#END verify interface
		
		self.repo = repo
		self.name = name
		
		if os.name == 'nt':
			# some oddity: on windows, python 2.5, it for some reason does not realize
			# that it has the config_writer property, but instead calls __getattr__
			# which will not yield the expected results. 'pinging' the members
			# with a dir call creates the config_writer property that we require 
			# ... bugs like these make me wonder wheter python really wants to be used
			# for production. It doesn't happen on linux though.
			dir(self)
		# END windows special handling
		
	def __getattr__(self, attr):
		"""Allows to call this instance like 
		remote.special( *args, **kwargs) to call git-remote special self.name"""
		if attr == "_config_reader":
			return super(Remote, self).__getattr__(attr)
		
		# sometimes, probably due to a bug in python itself, we are being called
		# even though a slot of the same name exists
		try:
			return self._config_reader.get(attr)
		except NoOptionError:
			return super(Remote, self).__getattr__(attr)
		# END handle exception
	
	def _config_section_name(self):
		return 'remote "%s"' % self.name
	
	def _set_cache_(self, attr):
		if attr == "_config_reader":
			self._config_reader = SectionConstraint(self.repo.config_reader(), self._config_section_name())
		else:
			super(Remote, self)._set_cache_(attr)
			
	
	def __str__(self):
		return self.name 
	
	def __repr__(self):
		return '<git.%s "%s">' % (self.__class__.__name__, self.name)
		
	def __eq__(self, other):
		return self.name == other.name
		
	def __ne__(self, other):
		return not ( self == other )
		
	def __hash__(self):
		return hash(self.name)
	
	@classmethod
	def iter_items(cls, repo):
		""":return: Iterator yielding Remote objects of the given repository"""
		for section in repo.config_reader("repository").sections():
			if not section.startswith('remote'):
				continue
			lbound = section.find('"')
			rbound = section.rfind('"')
			if lbound == -1 or rbound == -1:
				raise ValueError("Remote-Section has invalid format: %r" % section)
			yield Remote(repo, section[lbound+1:rbound])
		# END for each configuration section
		
	@property
	def refs(self):
		"""
		:return:
			IterableList of RemoteReference objects. It is prefixed, allowing 
			you to omit the remote path portion, i.e.::
			 remote.refs.master # yields RemoteReference('/refs/remotes/origin/master')"""
		out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
		out_refs.extend(RemoteReference.list_items(self.repo, remote=self.name))
		assert out_refs, "Remote %s did not have any references" % self.name
		return out_refs
		
	@property
	def stale_refs(self):
		"""
		:return:
			IterableList RemoteReference objects that do not have a corresponding 
			head in the remote reference anymore as they have been deleted on the 
			remote side, but are still available locally.
			
			The IterableList is prefixed, hence the 'origin' must be omitted. See
			'refs' property for an example."""
		out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
		for line in self.repo.git.remote("prune", "--dry-run", self).splitlines()[2:]:
			# expecting 
			# * [would prune] origin/new_branch
			token = " * [would prune] " 
			if not line.startswith(token):
				raise ValueError("Could not parse git-remote prune result: %r" % line)
			fqhn = "%s/%s" % (RemoteReference._common_path_default,line.replace(token, ""))
			out_refs.append(RemoteReference(self.repo, fqhn))
		# END for each line 
		return out_refs
	
	@classmethod
	def create(cls, repo, name, url, **kwargs):
		"""Create a new remote to the given repository
		:param repo: Repository instance that is to receive the new remote
		:param name: Desired name of the remote
		:param url: URL which corresponds to the remote's name
		:param kwargs:
			Additional arguments to be passed to the git-remote add command
			
		:return: New Remote instance
			
		:raise GitCommandError: in case an origin with that name already exists"""
		repo.git.remote( "add", name, url, **kwargs )
		return cls(repo, name)
	
	# add is an alias
	add = create
	
	@classmethod
	def remove(cls, repo, name ):
		"""Remove the remote with the given name"""
		repo.git.remote("rm", name)
		
	# alias
	rm = remove
		
	def rename(self, new_name):
		"""Rename self to the given new_name
		:return: self """
		if self.name == new_name:
			return self
		
		self.repo.git.remote("rename", self.name, new_name)
		self.name = new_name
		try:
			del(self._config_reader)		# it contains cached values, section names are different now
		except AttributeError:
			pass
		#END handle exception
		return self
		
	def update(self, **kwargs):
		"""Fetch all changes for this remote, including new branches which will 
		be forced in ( in case your local remote branch is not part the new remote branches
		ancestry anymore ).
		
		:param kwargs:
			Additional arguments passed to git-remote update
		
		:return: self """
		self.repo.git.remote("update", self.name)
		return self
	
	def fetch(self, refspec=None, progress=None, **kwargs):
		"""Fetch the latest changes for this remote
		
		:param refspec:
			A "refspec" is used by fetch and push to describe the mapping 
			between remote ref and local ref. They are combined with a colon in 
			the format <src>:<dst>, preceded by an optional plus sign, +. 
			For example: git fetch $URL refs/heads/master:refs/heads/origin means 
			"grab the master branch head from the $URL and store it as my origin 
			branch head". And git push $URL refs/heads/master:refs/heads/to-upstream 
			means "publish my master branch head as to-upstream branch at $URL". 
			See also git-push(1).
			
			Taken from the git manual
		:param progress: See 'push' method
		:param kwargs: Additional arguments to be passed to git-fetch
		:return:
			IterableList(FetchInfo, ...) list of FetchInfo instances providing detailed 
			information about the fetch results
			
		:note:
			As fetch does not provide progress information to non-ttys, we cannot make 
			it available here unfortunately as in the 'push' method."""
		return self.repo.fetch(self.name, refspec, progress, **kwargs)
		
	def pull(self, refspec=None, progress=None, **kwargs):
		"""Pull changes from the given branch, being the same as a fetch followed 
		by a merge of branch with your local branch.
		
		:param refspec: see 'fetch' method
		:param progress: see 'push' method
		:param kwargs: Additional arguments to be passed to git-pull
		:return: Please see 'fetch' method """
		return self.repo.pull(self.name, refspec, progress, **kwargs)
		
	def push(self, refspec=None, progress=None, **kwargs):
		"""Push changes from source branch in refspec to target branch in refspec.
		
		:param refspec: see 'fetch' method
		:param progress:
			Instance of type RemoteProgress allowing the caller to receive 
			progress information until the method returns.
			If None, progress information will be discarded
		
		:param kwargs: Additional arguments to be passed to git-push
		:return:
			IterableList(PushInfo, ...) iterable list of PushInfo instances, each 
			one informing about an individual head which had been updated on the remote 
			side.
			If the push contains rejected heads, these will have the PushInfo.ERROR bit set
			in their flags.
			If the operation fails completely, the length of the returned IterableList will
			be null."""
		return self.repo.push(self.name, refspec, progress, **kwargs)
		
	@property
	def config_reader(self):
		"""
		:return:
			GitConfigParser compatible object able to read options for only our remote.
			Hence you may simple type config.get("pushurl") to obtain the information"""
		return self._config_reader
	
	@property
	def config_writer(self):
		"""
		:return: GitConfigParser compatible object able to write options for this remote.
		:note:
			You can only own one writer at a time - delete it to release the 
			configuration file and make it useable by others.
			
			To assure consistent results, you should only query options through the 
			writer. Once you are done writing, you are free to use the config reader 
			once again."""
		writer = self.repo.config_writer()
		
		# clear our cache to assure we re-read the possibly changed configuration
		try:
			del(self._config_reader)
		except AttributeError:
			pass
		#END handle exception
		return SectionConstraint(writer, self._config_section_name())
