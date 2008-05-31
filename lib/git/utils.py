def dashify(string):
    return string.replace('_', '-')

def touch(filename):
    open(filename, "a").close()
