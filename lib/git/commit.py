# commit.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import re
import time

from actor import Actor
from lazy import LazyMixin
from tree import Tree
import diff
import stats

class Commit(LazyMixin):
    """
    Wraps a git Commit object.

    This class will act lazily on some of its attributes and will query the
    value on demand only if it involves calling the git binary.
    """
    def __init__(self, repo, id, tree=None, author=None, authored_date=None,
                 committer=None, committed_date=None, message=None, parents=None):
        """
        Instantiate a new Commit. All keyword arguments taking None as default will
        be implicitly set if id names a valid sha.

        The parameter documentation indicates the type of the argument after a colon ':'.

        ``id``
            is the sha id of the commit

        ``parents`` : list( Commit, ... )
            is a list of commit ids

        ``tree`` : Tree
            is the corresponding tree id

        ``author`` : Actor
            is the author string ( will be implicitly converted into an Actor object )

        ``authored_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst )
            is the authored DateTime

        ``committer`` : Actor
            is the committer string

        ``committed_date`` : (tm_year, tm_mon, tm_mday, tm_hour, tm_min, tm_sec, tm_wday, tm_yday, tm_isdst)
            is the committed DateTime

        ``message`` : string
            is the commit message

        Returns
            git.Commit
        """
        LazyMixin.__init__(self)

        self.repo = repo
        self.id = id
        self.parents = None
        self.tree = None
        self.author = author
        self.authored_date = authored_date
        self.committer = committer
        self.committed_date = committed_date
        self.message = message

        if self.id:
            if parents is not None:
                self.parents = [Commit(repo, p) for p in parents]
            if tree is not None:
                self.tree = Tree(repo, id=tree)

    def __bake__(self):
        """
        Called by LazyMixin superclass when the first uninitialized member needs
        to be set as it is queried.
        """
        temp = Commit.find_all(self.repo, self.id, max_count=1)[0]
        self.parents = temp.parents
        self.tree = temp.tree
        self.author = temp.author
        self.authored_date = temp.authored_date
        self.committer = temp.committer
        self.committed_date = temp.committed_date
        self.message = temp.message

    @property
    def id_abbrev(self):
        """
        Returns
            First 7 bytes of the commit's sha id as an abbreviation of the full string.
        """
        return self.id[0:7]

    @property
    def summary(self):
        """
        Returns
            First line of the commit message.
        """
        return self.message.split('\n', 1)[0]

    @classmethod
    def count(cls, repo, ref, path=''):
        """
        Count the number of commits reachable from this ref

        ``repo``
            is the Repo

        ``ref``
            is the ref from which to begin (SHA1 or name)

        ``path``
            is an optional path

        Returns
            int
        """
        return len(repo.git.rev_list(ref, '--', path).strip().splitlines())

    @classmethod
    def find_all(cls, repo, ref, path='', **kwargs):
        """
        Find all commits matching the given criteria.
        ``repo``
            is the Repo

        ``ref``
            is the ref from which to begin (SHA1 or name)

        ``path``
            is an optinal path, if set only Commits that include the path
            will be considered

        ``kwargs``
            optional keyword arguments to git where
            ``max_count`` is the maximum number of commits to fetch
            ``skip`` is the number of commits to skip

        Returns
            git.Commit[]
        """
        options = {'pretty': 'raw'}
        options.update(kwargs)

        output = repo.git.rev_list(ref, '--', path, **options)
        return cls.list_from_string(repo, output)

    @classmethod
    def list_from_string(cls, repo, text):
        """
        Parse out commit information into a list of Commit objects

        ``repo``
            is the Repo

        ``text``
            is the text output from the git-rev-list command (raw format)

        Returns
            git.Commit[]
        """
        lines = [l for l in text.splitlines() if l.strip()]

        commits = []

        while lines:
            id = lines.pop(0).split()[1]
            tree = lines.pop(0).split()[1]

            parents = []
            while lines and lines[0].startswith('parent'):
                parents.append(lines.pop(0).split()[-1])
            author, authored_date = cls.actor(lines.pop(0))
            committer, committed_date = cls.actor(lines.pop(0))

            messages = []
            while lines and lines[0].startswith('    '):
                messages.append(lines.pop(0).strip())

            message = '\n'.join(messages)

            commits.append(Commit(repo, id=id, parents=parents, tree=tree, author=author, authored_date=authored_date,
                                  committer=committer, committed_date=committed_date, message=message))

        return commits

    @classmethod
    def diff(cls, repo, a, b=None, paths=None):
        """
        Creates diffs between a tree and the index or between two trees:

        ``repo``
            is the Repo

        ``a``
            is a named commit

        ``b``
            is an optional named commit.  Passing a list assumes you
            wish to omit the second named commit and limit the diff to the
            given paths.

        ``paths``
            is a list of paths to limit the diff to.

        Returns
            git.Diff[]::

             between tree and the index if only a is given
             between two trees if a and b are given and are commits
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
        text = repo.git.diff('-M', full_index=True, *paths)
        return diff.Diff.list_from_string(repo, text)

    @property
    def diffs(self):
        """
        Returns
            git.Diff[]
            Diffs between this commit and its first parent or all changes if this
            commit is the first commit and has no parent.
        """
        if not self.parents:
            d = self.repo.git.show(self.id, '-M', full_index=True, pretty='raw')
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
        """
        Create a git stat from changes between this commit and its first parent
        or from all changes done if this is the very first commit.

        Return
            git.Stats
        """
        if not self.parents:
            text = self.repo.git.diff_tree(self.id, '--', numstat=True, root=True)
            text2 = ""
            for line in text.splitlines()[1:]:
                (insertions, deletions, filename) = line.split("\t")
                text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
            text = text2
        else:
            text = self.repo.git.diff(self.parents[0].id, self.id, '--', numstat=True)
        return stats.Stats.list_from_string(self.repo, text)

    def __str__(self):
        """ Convert commit to string which is SHA1 """
        return self.id

    def __repr__(self):
        return '<git.Commit "%s">' % self.id

    @classmethod
    def actor(cls, line):
        """
        Parse out the actor (author or committer) info

        Returns
            [Actor, gmtime(acted at time)]
        """
        m = re.search(r'^.+? (.*) (\d+) .*$', line)
        actor, epoch = m.groups()
        return [Actor.from_string(actor), time.gmtime(int(epoch))]
