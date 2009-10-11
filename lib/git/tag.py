# tag.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import commit
import base

class TagRef(base.Ref):
	"""
	Class representing a lightweight tag reference which either points to a commit 
	or to a tag object. In the latter case additional information, like the signature
	or the tag-creator, is available.
	
	This tag object will always point to a commit object, but may carray additional
	information in a tag object::
	
	 tagref = TagRef.find_all(repo)[0]
	 print tagref.commit.message
	 if tagref.tag is not None:
		print tagref.tag.message
	"""
	
	__slots__ = "tag"
	
	def __init__(self, path, commit_or_tag):
		"""
		Initialize a newly instantiated Tag

		``path``
			is the full path to the tag

		``commit_or_tag``
			is the Commit or TagObject that this tag ref points to
		"""
		super(TagRef, self).__init__(path, commit_or_tag)
		self.tag = None
		
		if commit_or_tag.type == "tag":
			self.tag = commit_or_tag
		# END tag object handling 
	
	@property
	def commit(self):
		"""
		Returns
			Commit object the tag ref points to
		"""
		if self.object.type == "commit":
			return self.object
		# it is a tag object
		return self.object.object

	@classmethod
	def find_all(cls, repo, common_path = "refs/tags", **kwargs):
		"""
		Returns
			git.Tag[]
			
		For more documentation, please refer to git.base.Ref.find_all
		"""
		return super(TagRef,cls).find_all(repo, common_path, **kwargs)
		
		
# provide an alias
Tag = TagRef
		
class TagObject(base.Object):
	"""
	Non-Lightweight tag carrying additional information about an object we are pointing 
	to.
	"""
	type = "tag"
	__slots__ = ( "object", "tag", "tagger", "tagged_date", "message" )
		
	def __init__(self, repo, id, size=None, object=None, tag=None, 
				tagger=None, tagged_date=None, message=None):
		"""
		Initialize a tag object with additional data
		
		``repo``
			repository this object is located in
			
		``id``
			SHA1 or ref suitable for git-rev-parse
			
		``size``
			Size of the object's data in bytes
			
		 ``object``
			Object instance of object we are pointing to
		 
		 ``tag``
			name of this tag
			
		 ``tagger``
			Actor identifying the tagger
			
		  ``tagged_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst)
			is the DateTime of the tag creation
		"""
		super(TagObject, self).__init__(repo, id , size)
		self.object = object
		self.tag = tag
		self.tagger = tagger
		self.tagged_date = tagged_date
		self.message = message
		
	def __bake__(self):
		super(TagObject, self).__bake__()
		
		output = self.repo.git.cat_file(self.type,self.id)
		lines = output.split("\n")
		
		obj, hexsha = lines[0].split(" ")		# object <hexsha>
		type_token, type_name = lines[1].split(" ") # type <type_name>
		self.object = base.Object.get_type_by_name(type_name)(self.repo, hexsha)
		
		self.tag = lines[2][4:]  # tag <tag name>
		
		tagger_info = lines[3][7:]# tagger <actor> <date>
		self.tagger, self.tagged_date = commit.Commit._actor(tagger_info)
		
		# line 4 empty - check git source to figure out purpose
		self.message = "\n".join(lines[5:])
		
		
