def dashify(string):
    return string.replace('_', '-')

def touch(filename):
    open(filename, "a").close()

def pop_key(d, key):
    value = d.get(key, None)
    if key in d:
        del d[key]
    return value
