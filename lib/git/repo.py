# repo.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os
import re
import gzip
import StringIO
from errors import InvalidGitRepositoryError, NoSuchPathError
from utils import touch, is_git_dir
from cmd import Git
from head import Head
from blob import Blob
from tag import Tag
from commit import Commit
from tree import Tree

class Repo(object):
    DAEMON_EXPORT_FILE = 'git-daemon-export-ok'

    def __init__(self, path=None):
        """
        Create a new Repo instance

        ``path``
            is the path to either the root git directory or the bare git repo

        Examples::

            repo = Repo("/Users/mtrier/Development/git-python")
            repo = Repo("/Users/mtrier/Development/git-python.git")

        Returns
            ``git.Repo``
        """

        epath = os.path.abspath(os.path.expanduser(path or os.getcwd()))

        if not os.path.exists(epath):
            raise NoSuchPathError(epath)

        self.path = None
        curpath = epath
        while curpath:
            if is_git_dir(curpath):
                self.bare = True
                self.path = curpath
                self.wd = curpath
                break
            gitpath = os.path.join(curpath, '.git')
            if is_git_dir(gitpath):
                self.bare = False
                self.path = gitpath
                self.wd = curpath
                break
            curpath, dummy = os.path.split(curpath)
            if not dummy:
                break

        if self.path is None:
           raise InvalidGitRepositoryError(epath)

        self.git = Git(self.wd)

    # Description property
    def _get_description(self):
        filename = os.path.join(self.path, 'description')
        return file(filename).read().rstrip()

    def _set_description(self, descr):
        filename = os.path.join(self.path, 'description')
        file(filename, 'w').write(descr+'\n')

    description = property(_get_description, _set_description,
                           doc="the project's description")
    del _get_description
    del _set_description

    @property
    def heads(self):
        """
        A list of ``Head`` objects representing the branch heads in
        this repo

        Returns
            ``git.Head[]``
        """
        return Head.find_all(self)

    # alias heads
    branches = heads

    @property
    def tags(self):
        """
        A list of ``Tag`` objects that are available in this repo

        Returns
            ``git.Tag[]``
        """
        return Tag.find_all(self)

    def commits(self, start='master', path='', max_count=10, skip=0):
        """
        A list of Commit objects representing the history of a given ref/commit

        ``start``
            is the branch/commit name (default 'master')

         ``path``
            is an optional path

         ``max_count``
            is the maximum number of commits to return (default 10)

          ``skip``
            is the number of commits to skip (default 0)

        Returns
            ``git.Commit[]``
        """
        options = {'max_count': max_count,
                   'skip': skip}

        return Commit.find_all(self, start, path, **options)

    def commits_between(self, frm, to, path = ''):
        """
        The Commits objects that are reachable via ``to`` but not via ``frm``
        Commits are returned in chronological order.

        ``from``
            is the branch/commit name of the younger item

        ``to``
            is the branch/commit name of the older item

        ``path``
            is an optional path

        Returns
            ``git.Commit[]``
        """
        return reversed(Commit.find_all(self, "%s..%s" % (frm, to)))

    def commits_since(self, start='master', path='', since='1970-01-01'):
        """
        The Commits objects that are newer than the specified date.
        Commits are returned in chronological order.

        ``start``
            is the branch/commit name (default 'master')

        ``path``
            is an optinal path

        ``since``
            is a string represeting a date/time

        Returns
            ``git.Commit[]``
        """
        options = {'since': since}

        return Commit.find_all(self, start, path, **options)

    def commit_count(self, start='master', path=''):
        """
        The number of commits reachable by the given branch/commit

        ``start``
            is the branch/commit name (default 'master')

        ``path``
            is an optinal path

        Returns
            int
        """
        return Commit.count(self, start, path)

    def commit(self, id, path = ''):
        """
        The Commit object for the specified id

        ``id``
            is the SHA1 identifier of the commit

        ``path``
            is an optinal path

        Returns
            git.Commit
        """
        options = {'max_count': 1}

        commits = Commit.find_all(self, id, path, **options)

        if not commits:
            raise ValueError, 'Invalid identifier %s' % id
        return commits[0]

    def commit_deltas_from(self, other_repo, ref='master', other_ref='master'):
        """
        Returns a list of commits that is in ``other_repo`` but not in self

        Returns 
            ``git.Commit[]``
        """
        repo_refs = self.git.rev_list(ref, '--').strip().splitlines()
        other_repo_refs = other_repo.git.rev_list(other_ref, '--').strip().splitlines()

        diff_refs = list(set(other_repo_refs) - set(repo_refs))
        return map(lambda ref: Commit.find_all(other_repo, ref, max_count=1)[0], diff_refs)

    def tree(self, treeish='master'):
        """
        The Tree object for the given treeish reference

        ``treeish``
            is the reference (default 'master')

        Examples::

          repo.tree('master')


        Returns
            ``git.Tree``
        """
        return Tree(self, id=treeish)

    def blob(self, id):
        """
        The Blob object for the given id

        ``id``
            is the SHA1 id of the blob

        Returns
            ``git.Blob``
        """
        return Blob(self, id=id)

    def log(self, commit='master', path=None, **kwargs):
        """
        The commit log for a treeish

        Returns
            ``git.Commit[]``
        """
        options = {'pretty': 'raw'}
        options.update(kwargs)
        arg = [commit, '--']
        if path:
            arg.append(path)
        commits = self.git.log(*arg, **options)
        return Commit.list_from_string(self, commits)

    def diff(self, a, b, *paths):
        """
        The diff from commit ``a`` to commit ``b``, optionally restricted to the given file(s)

        ``a``
            is the base commit
        ``b``
            is the other commit

        ``paths``
            is an optional list of file paths on which to restrict the diff
        """
        return self.git.diff(a, b, '--', *paths)

    def commit_diff(self, commit):
        """
        The commit diff for the given commit
          ``commit`` is the commit name/id

        Returns
            ``git.Diff[]``
        """
        return Commit.diff(self, commit)

    @classmethod
    def init_bare(self, path, mkdir=True, **kwargs):
        """
        Initialize a bare git repository at the given path

        ``path``
            is the full path to the repo (traditionally ends with /<name>.git)

        ``mkdir``
            if specified will create the repository directory if it doesn't
            already exists. Creates the directory with a mode=0755.

        ``kwargs``
            is any additional options to the git init command

        Examples::

            git.Repo.init_bare('/var/git/myrepo.git')

        Returns
            ``git.Repo`` (the newly created repo)
        """

        if mkdir and not os.path.exists(path):
            os.makedirs(path, 0755)

        git = Git(path)
        output = git.init('--bare', **kwargs)
        return Repo(path)
    create = init_bare

    def fork_bare(self, path, **kwargs):
        """
        Fork a bare git repository from this repo

        ``path``
            is the full path of the new repo (traditionally ends with /<name>.git)

        ``options``
            is any additional options to the git clone command

        Returns
            ``git.Repo`` (the newly forked repo)
        """
        options = {'bare': True}
        options.update(kwargs)
        self.git.clone(self.path, path, **options)
        return Repo(path)

    def archive_tar(self, treeish='master', prefix=None):
        """
        Archive the given treeish

        ``treeish``
            is the treeish name/id (default 'master')

        ``prefix``
            is the optional prefix

        Examples::

            >>> repo.archive_tar
            <String containing tar archive>

            >>> repo.archive_tar('a87ff14')
            <String containing tar archive for commit a87ff14>

            >>> repo.archive_tar('master', 'myproject/')
            <String containing tar archive and prefixed with 'myproject/'>

        Returns
            str (containing tar archive)
        """
        options = {}
        if prefix:
            options['prefix'] = prefix
        return self.git.archive(treeish, **options)

    def archive_tar_gz(self, treeish='master', prefix=None):
        """
        Archive and gzip the given treeish

        ``treeish``
            is the treeish name/id (default 'master')

        ``prefix``
            is the optional prefix

        Examples::

            >>> repo.archive_tar_gz
            <String containing tar.gz archive>

            >>> repo.archive_tar_gz('a87ff14')
            <String containing tar.gz archive for commit a87ff14>

            >>> repo.archive_tar_gz('master', 'myproject/')
            <String containing tar.gz archive and prefixed with 'myproject/'>

        Returns
            str (containing tar.gz archive)
        """
        kwargs = {}
        if prefix:
            kwargs['prefix'] = prefix
        resultstr =  self.git.archive(treeish, **kwargs)
        sio = StringIO.StringIO()
        gf = gzip.GzipFile(fileobj=sio, mode ='wb')
        gf.write(resultstr)
        gf.close()
        return sio.getvalue()

    def _get_daemon_export(self):
        filename = os.path.join(self.path, self.DAEMON_EXPORT_FILE)
        return os.path.exists(filename)

    def _set_daemon_export(self, value):
        filename = os.path.join(self.path, self.DAEMON_EXPORT_FILE)
        fileexists = os.path.exists(filename)
        if value and not fileexists:
            touch(filename)
        elif not value and fileexists:
            os.unlink(filename)

    daemon_export = property(_get_daemon_export, _set_daemon_export,
                             doc="git-daemon export of this repository")
    del _get_daemon_export
    del _set_daemon_export

    def _get_alternates(self):
        """
        The list of alternates for this repo

        Returns
            list[str] (pathnames of alternates)
        """
        alternates_path = os.path.join(self.path, 'objects', 'info', 'alternates')

        if os.path.exists(alternates_path):
            try:
                f = open(alternates_path)
                alts = f.read()
            finally:
                f.close()
            return alts.strip().splitlines()
        else:
            return []

    def _set_alternates(self, alts):
        """
        Sets the alternates

        ``alts``
            is the Array of String paths representing the alternates

        Returns
            None
        """
        for alt in alts:
            if not os.path.exists(alt):
                raise NoSuchPathError("Could not set alternates. Alternate path %s must exist" % alt)

        if not alts:
            os.remove(os.path.join(self.path, 'objects', 'info', 'alternates'))
        else:
            try:
                f = open(os.path.join(self.path, 'objects', 'info', 'alternates'), 'w')
                f.write("\n".join(alts))
            finally:
                f.close()

    alternates = property(_get_alternates, _set_alternates)

    @property
    def is_dirty(self):
        """
        Return the status of the working directory.

        Returns
            ``True``, if the working directory has any uncommitted changes,
            otherwise ``False``

        """
        if self.bare:
            # Bare repositories with no associated working directory are
            # always consired to be clean.
            return False

        return len(self.git.diff('HEAD', '--').strip()) > 0

    @property
    def active_branch(self):
        """
        The name of the currently active branch.

        Returns
            str (the branch name)
        """
        branch = self.git.symbolic_ref('HEAD').strip()
        if branch.startswith('refs/heads/'):
            branch = branch[len('refs/heads/'):]

        return branch

    def __repr__(self):
        return '<git.Repo "%s">' % self.path
