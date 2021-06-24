import warnings


class Watcher(type):
    def __init__(cls, name, bases, clsdict):
        for base in bases:
            if type(base) == Watcher:
                warnings.warn(f"GitPython Iterable subclassed by {name}. "
                              "Iterable is deprecated due to naming clash, "
                              "Use IterableObj instead \n",
                              DeprecationWarning,
                              stacklevel=2)


class SuperClass(metaclass=Watcher):
    pass


class SubClass0(SuperClass):
    pass


class SubClass1(SuperClass):
    print("test")


class normo():
    print("wooo")
