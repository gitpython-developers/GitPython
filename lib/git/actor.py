# actor.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re

class Actor(object):
    """Actors hold information about a person acting on the repository. They 
    can be committers and authors or anything with a name and an email as 
    mentioned in the git log entries."""
    # precompiled regex
    name_only_regex = re.compile( r'<(.+)>' )
    name_email_regex = re.compile( r'(.*) <(.+?)>' ) 
    
    def __init__(self, name, email):
        self.name = name
        self.email = email

    def __eq__(self, other):
        return self.name == other.name and self.email == other.email
        
    def __ne__(self, other):
        return not (self == other)
        
    def __hash__(self):
        return hash((self.name, self.email))

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<git.Actor "%s <%s>">' % (self.name, self.email)

    @classmethod
    def _from_string(cls, string):
        """
        Create an Actor from a string.

        ``str``
            is the string, which is expected to be in regular git format

        Format
            John Doe <jdoe@example.com>

        Returns
            Actor
        """
        m = cls.name_email_regex.search(string)
        if m:
            name, email = m.groups()
            return Actor(name, email)
        else:
            m = cls.name_only_regex.search(string)
            if m:
                return Actor(m.group(1), None)
            else:
                # assume best and use the whole string as name
                return Actor(string, None)
            # END special case name
        # END handle name/email matching
