# lazy.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class LazyMixin(object):
    lazy_properties = []

    def __init__(self):
        self.__baked__ = False

    def __getattribute__(self, attr):
        val = object.__getattribute__(self, attr)
        if val is not None:
            return val
        else:
            self.__prebake__()
            return object.__getattribute__(self, attr)

    def __bake__(self):
        """ This method should be overridden in the derived class. """
        raise NotImplementedError(" '__bake__' method has not been implemented.")

    def __prebake__(self):
        if self.__baked__:
            return
        self.__bake__()
        self.__baked__ = True

    def __bake_it__(self):
        self.__baked__ = True
