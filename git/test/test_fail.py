import sys


def test_add3():
    assert 1 + 1 == 2

    # fail in python 2 only
    assert sys.version_info.major == 3
