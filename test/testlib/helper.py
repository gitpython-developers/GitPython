import os

GIT_REPO = os.path.join(os.path.dirname(__file__), "..", "..")

def fixture(name):    
    file = open(os.path.join(os.path.dirname(__file__), "..", "fixtures", name))
    return file.read()

def absolute_project_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))