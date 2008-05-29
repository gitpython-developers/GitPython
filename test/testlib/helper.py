import os

GIT_REPO = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

def fixture_path(name):
    test_dir = os.path.dirname( os.path.dirname(__file__) )
    return os.path.join(test_dir, "fixtures", name)

def fixture(name):
    return open(fixture_path(name)).read()

def absolute_project_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
