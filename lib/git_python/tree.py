import os
from lazy import LazyMixin
import blob

class Tree(LazyMixin):
    def __init__(self, repo, **kwargs):
        LazyMixin.__init__(self)
        self.repo = repo
        self.id = None
        self.contents = None
        
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __bake__(self):
        temp = Tree.construct(self.repo, self.id)
        self.contents = temp.contents

    @classmethod
    def construct(cls, repo, treeish, paths = []):
        output = repo.git.ls_tree(treeish, *paths)    
        return Tree(repo, **{'id': treeish}).construct_initialize(repo, treeish, output)

    def construct_initialize(self, repo, id, text):
        self.repo = repo
        self.id = id
        self.contents = []
        self.__baked__ = False
        
        for line in text.splitlines():
            self.contents.append(self.content_from_string(self.repo, line))
        
        self.contents = [c for c in self.contents if c is not None]

        self.__bake_it__()
        return self

    def content_from_string(self, repo, text):
        """
        Parse a content item and create the appropriate object
        
        ``repo``
            is the Repo
         
         ``text``
            is the single line containing the items data in `git ls-tree` format

        Returns
            ``GitPython.Blob`` or ``GitPython.Tree``
        """
        try:
            mode, typ, id, name = text.expandtabs(1).split(" ", 4)
        except:
            return None
            
        if typ == "tree":
            return Tree(repo, **{'id': id, 'mode': mode, 'name': name})
        elif typ == "blob":
            return blob.Blob(repo, **{'id': id, 'mode': mode, 'name': name})
        elif typ == "commit":
            return None
        else:
          raise(TypeError, "Invalid type: %s" % typ)

    def __div__(self, file):
        """
        Find the named object in this tree's contents

        Examples::
        
            >>> Repo('/path/to/python-git').tree/'lib'
            <GitPython.Tree "6cc23ee138be09ff8c28b07162720018b244e95e">
            >>> Repo('/path/to/python-git').tree/'README.txt'
            <GitPython.Blob "8b1e02c0fb554eed2ce2ef737a68bb369d7527df">
        
        Returns
            ``GitPython.Blob`` or ``GitPython.Tree`` or ``None`` if not found
        """
        contents = [c for c in self.contents if c.name == file]
        return contents and contents[0] or None
    
    @property
    def basename(self):
        os.path.basename(self.name)
    
    def __repr__(self):
        return '<GitPython.Tree "%s">' % self.id
