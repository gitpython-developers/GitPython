# method_missing.py
# Copyright (C) 2008 Michael Trier (mtrier@gmail.com) and contributors
# Portions derived from http://blog.iffy.us/?p=43
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

class MethodMissingMixin(object):
    """
    A Mixin' to implement the 'method_missing' Ruby-like protocol.

    Ideas were `taken from the following blog post 
    <http://blog.iffy.us/?p=43>`_
    """
    def __getattr__(self, attr):
        class MethodMissing(object):
            def __init__(self, wrapped, method):
                self.__wrapped__ = wrapped
                self.__method__ = method
            def __call__(self, *args, **kwargs):
                return self.__wrapped__.method_missing(self.__method__, *args, **kwargs)
        return MethodMissing(self, attr)

    def method_missing(self, *args, **kwargs):
        """ This method should be overridden in the derived class. """
        raise NotImplementedError(str(self.__wrapped__) + " 'method_missing' method has not been implemented.")
