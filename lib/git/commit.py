import re
import time

from actor import Actor
from lazy import LazyMixin
import tree
import diff
import stats

class Commit(LazyMixin):
    def __init__(self, repo, **kwargs):
        """
        Instantiate a new Commit

        ``id``
            is the id of the commit

        ``parents``
            is a list of commit ids (will be converted into Commit instances)

        ``tree``
            is the correspdonding tree id (will be converted into a Tree object)

        ``author``
            is the author string

        ``authored_date``
            is the authored DateTime

        ``committer``
            is the committer string

        ``committed_date``
            is the committed DateTime

        ``message``
            is the first line of the commit message

        Returns
            GitPython.Commit
        """
        LazyMixin.__init__(self)

        self.repo = repo
        self.id = None
        self.tree = None
        self.author = None
        self.authored_date = None
        self.committer = None
        self.committed_date = None
        self.message = None
        self.parents = None

        for k, v in kwargs.items():
            setattr(self, k, v)

        if self.id:
            if 'parents' in kwargs:
                self.parents = map(lambda p: Commit(repo, **{'id': p}), kwargs['parents'])
            if 'tree' in kwargs:
                self.tree = tree.Tree(repo, **{'id': kwargs['tree']})

    def __bake__(self):
        temp = Commit.find_all(self.repo, self.id, **{'max_count': 1})[0]
        self.parents = temp.parents
        self.tree = temp.tree
        self.author = temp.author
        self.authored_date = temp.authored_date
        self.committer = temp.committer
        self.committed_date = temp.committed_date
        self.message = temp.message

    @property
    def id_abbrev(self):
        return self.id[0:7]

    @classmethod
    def count(cls, repo, ref):
        """
        Count the number of commits reachable from this ref

        ``repo``
            is the Repo

        ``ref``
            is the ref from which to begin (SHA1 or name)

        Returns
            int
        """
        return len(repo.git.rev_list(ref).strip().splitlines())

    @classmethod
    def find_all(cls, repo, ref, **kwargs):
        """
        Find all commits matching the given criteria.
        ``repo``
            is the Repo

        ``ref``
            is the ref from which to begin (SHA1 or name)

        ``options``
            is a Hash of optional arguments to git where
            ``max_count`` is the maximum number of commits to fetch
            ``skip`` is the number of commits to skip

        Returns
            GitPython.Commit[]
        """
        options = {'pretty': 'raw'}
        options.update(kwargs)

        output = repo.git.rev_list(ref, **options)
        return cls.list_from_string(repo, output)

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Parse out commit information into a list of Commit objects

        ``repo``
            is the Repo

        ``text``
            is the text output from the git command (raw format)

        Returns
            GitPython.Commit[]
        """
        lines = [l for l in text.splitlines() if l.strip()]

        commits = []

        while lines:
            id = lines.pop(0).split()[-1]
            tree = lines.pop(0).split()[-1]

            parents = []
            while lines and re.search(r'^parent', lines[0]):
                parents.append(lines.pop(0).split()[-1])
            author, authored_date = cls.actor(lines.pop(0))
            committer, committed_date = cls.actor(lines.pop(0))

            messages = []
            while lines and re.search(r'^ {4}', lines[0]):
                messages.append(lines.pop(0).strip())

            message = messages and messages[0] or ''

            commits.append(Commit(repo, id=id, parents=parents, tree=tree, author=author, authored_date=authored_date, 
                                  committer=committer, committed_date=committed_date, message=message))

        return commits

    @classmethod
    def diff(cls, repo, a, b = None, paths = None):
        """
        Show diffs between two trees:

        ``repo``
            is the Repo

        ``a``
            is a named commit

        ``b``
            is an optional named commit.  Passing a list assumes you
            wish to omit the second named commit and limit the diff to the
            given paths.

        ``paths``
            is a list of paths to limit the diff.

        Returns
            GitPython.Diff[]
        """
        paths = paths or []

        if isinstance(b, list):
            paths = b
            b = None

        if paths:
            paths.insert(0, "--")

        if b:
            paths.insert(0, b)
        paths.insert(0, a)
        text = repo.git.diff(*paths, **{'full_index': True})
        return diff.Diff.list_from_string(repo, text)

    @property
    def diffs(self):
        if not self.parents:
            d = self.repo.git.show(self.id, **{'full_index': True, 'pretty': 'raw'})
            if re.search(r'diff --git a', d):
                if not re.search(r'^diff --git a', d):
                    p = re.compile(r'.+?(diff --git a)', re.MULTILINE | re.DOTALL)
                    d = p.sub(r'diff --git a', d, 1)
            else:
                d = ''
            return diff.Diff.list_from_string(self.repo, d)
        else:
            return self.diff(self.repo, self.parents[0].id, self.id)

    @property
    def stats(self):
        if not self.parents:
            text = self.repo.git.diff(self.id, **{'numstat': True})
            text2 = ""
            for line in text.splitlines():
                (insertions, deletions, filename) = line.split("\t")
                text2 += "%s\t%s\t%s\n" % (deletions, insertions, filename)
            text = text2
        else:
            text = self.repo.git.diff(self.parents[0].id, self.id, **{'numstat': True})
        return stats.Stats.list_from_string(self.repo, text)

    def __str__(self):
        """ Convert commit to string which is SHA1 """
        return self.id

    def __repr__(self):
        return '<GitPython.Commit "%s">' % self.id

    @classmethod
    def actor(cls, line):
        """
        Parse out the actor (author or committer) info

        Returns
            [str (actor name and email), time (acted at time)]
        """
        m = re.search(r'^.+? (.*) (\d+) .*$', line)
        actor, epoch = m.groups()
        return [Actor.from_string(actor), time.gmtime(int(epoch))]
