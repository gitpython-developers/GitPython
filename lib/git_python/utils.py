def shell_escape(string):
    return str(string).replace("'", "\\\\'")

def dashify(string):
    return string.replace('_', '-')

def touch(filename):
    open(filename, "a").close()
