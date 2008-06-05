class MethodMissingMixin(object):
    """
    A Mixin' to implement the 'method_missing' Ruby-like protocol.

    This was `taken from a blog post <http://blog.iffy.us/?p=43>`_
    """
    def __getattr__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except:
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
