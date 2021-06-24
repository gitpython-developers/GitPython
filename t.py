class Watcher(type):
    def __init__(cls, name, bases, clsdict):
        [print("ooooo") for base in bases if issubclass(base, name)]
        super(Watcher, cls).__init__(name, bases, clsdict)


class SuperClass(metaclass=Watcher):
    pass


class SubClass0(SuperClass):
    pass


class SubClass1(SuperClass):
    print("test")

class normo():
    print("wooo")
