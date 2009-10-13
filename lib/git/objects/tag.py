# objects.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing all object based types.
"""
import base
import commit
from utils import get_object_type_by_name

class TagObject(base.Object):
	"""
	Non-Lightweight tag carrying additional information about an object we are pointing 
	to.
	"""
	type = "tag"
	__slots__ = ( "object", "tag", "tagger", "tagged_date", "message" )
		
	def __init__(self, repo, id, object=None, tag=None, 
				tagger=None, tagged_date=None, message=None):
		"""
		Initialize a tag object with additional data
		
		``repo``
			repository this object is located in
			
		``id``
			SHA1 or ref suitable for git-rev-parse
			
		 ``object``
			Object instance of object we are pointing to
		 
		 ``tag``
			name of this tag
			
		 ``tagger``
			Actor identifying the tagger
			
		  ``tagged_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst)
			is the DateTime of the tag creation
		"""
		super(TagObject, self).__init__(repo, id )
		self._set_self_from_args_(locals())
		
	def _set_cache_(self, attr):
		"""
		Cache all our attributes at once
		"""
		if attr in self.__slots__:
			output = self.repo.git.cat_file(self.type,self.id)
			lines = output.split("\n")
			
			obj, hexsha = lines[0].split(" ")		# object <hexsha>
			type_token, type_name = lines[1].split(" ") # type <type_name>
			self.object = get_object_type_by_name(type_name)(self.repo, hexsha)
			
			self.tag = lines[2][4:]  # tag <tag name>
			
			tagger_info = lines[3][7:]# tagger <actor> <date>
			self.tagger, self.tagged_date = commit.Commit._actor(tagger_info)
			
			# line 4 empty - check git source to figure out purpose
			self.message = "\n".join(lines[5:])
		# END check our attributes
		else:
			super(TagObject, self)._set_cache_(attr)
		
		

