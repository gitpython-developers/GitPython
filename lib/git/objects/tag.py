# objects.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing all object based types.
"""
import base
import utils

class TagObject(base.Object):
    """
    Non-Lightweight tag carrying additional information about an object we are pointing 
    to.
    """
    type = "tag"
    __slots__ = ( "object", "tag", "tagger", "tagged_date", "tagger_tz_offset", "message" )
        
    def __init__(self, repo, sha, object=None, tag=None, 
                tagger=None, tagged_date=None, tagger_tz_offset=None, message=None):
        """
        Initialize a tag object with additional data
        
        ``repo``
            repository this object is located in
            
        ``sha``
            SHA1 or ref suitable for git-rev-parse
            
         ``object``
            Object instance of object we are pointing to
         
         ``tag``
            name of this tag
            
         ``tagger``
            Actor identifying the tagger
            
          ``tagged_date`` : int_seconds_since_epoch
            is the DateTime of the tag creation - use time.gmtime to convert 
            it into a different format

        ``tagged_tz_offset``: int_seconds_west_of_utc
          is the timezone that the authored_date is in

        """
        super(TagObject, self).__init__(repo, sha )
        self._set_self_from_args_(locals())
        
    def _set_cache_(self, attr):
        """
        Cache all our attributes at once
        """
        if attr in TagObject.__slots__:
            lines = self.data.splitlines()
            
            obj, hexsha = lines[0].split(" ")       # object <hexsha>
            type_token, type_name = lines[1].split(" ") # type <type_name>
            self.object = utils.get_object_type_by_name(type_name)(self.repo, hexsha)
            
            self.tag = lines[2][4:]  # tag <tag name>
            
            tagger_info = lines[3][7:]# tagger <actor> <date>
            self.tagger, self.tagged_date, self.tagger_tz_offset = utils.parse_actor_and_date(tagger_info)
            
            # line 4 empty - it could mark the beginning of the next header
            # in csse there really is no message, it would not exist. Otherwise 
            # a newline separates header from message
            if len(lines) > 5:
                self.message = "\n".join(lines[5:])
            else:
                self.message = ''
        # END check our attributes
        else:
            super(TagObject, self)._set_cache_(attr)
        
        

