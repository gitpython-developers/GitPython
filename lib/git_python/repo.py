import os
import re
from errors import InvalidGitRepositoryError, NoSuchPathError
from utils import touch
from git import Git
from head import Head
from blob import Blob
from tag import Tag
from commit import Commit
from tree import Tree

class Repo(object):
    DAEMON_EXPORT_FILE = 'git-daemon-export-ok'

    def __init__(self, path):
        """
        Create a new Repo instance

        ``path``
            is the path to either the root git directory or the bare git repo

        Examples::

            repo = Repo("/Users/mtrier/Development/git-python")
            repo = Repo("/Users/mtrier/Development/git-python.git")

        Returns
            ``GitPython.Repo``
        """
        epath = os.path.abspath(path)

        if os.path.exists(os.path.join(epath, '.git')):
            self.path = os.path.join(epath, '.git')
            self.bare = False
        elif os.path.exists(epath) and re.search('\.git$', epath):
            self.path = epath
            self.bare = True
        elif os.path.exists(epath):
            raise InvalidGitRepositoryError(epath)
        else:
            raise NoSuchPathError(epath)
        self.git = Git(self.path)

    @property
    def description(self):
        """
        The project's description. Taken verbatim from GIT_REPO/description

        Returns
            str
        """
        try:
            f = open(os.path.join(self.path, 'description'))
            result = f.read()
            return result.rstrip()
        finally:
            f.close()

    @property
    def heads(self):
        """
        A list of ``Head`` objects representing the branch heads in
        this repo

        Returns
            ``GitPython.Head[]``
        """
        return Head.find_all(self)

    # alias heads
    branches = heads

    @property
    def tags(self):
        """
        A list of ``Tag`` objects that are available in this repo

        Returns
            ``GitPython.Tag[]``
        """
        return Tag.find_all(self)

    def commits(self, start = 'master', max_count = 10, skip = 0):
        """
        A list of Commit objects representing the history of a given ref/commit

        ``start``
            is the branch/commit name (default 'master')

         ``max_count``
            is the maximum number of commits to return (default 10)

          ``skip``
            is the number of commits to skip (default 0)

        Returns
            ``GitPython.Commit[]``
        """
        options = {'max_count': max_count,
                   'skip': skip}

        return Commit.find_all(self, start, **options)

    def commits_between(self, frm, to):
        """
        The Commits objects that are reachable via ``to`` but not via ``frm``
        Commits are returned in chronological order.

        ``from``
            is the branch/commit name of the younger item

        ``to``
            is the branch/commit name of the older item

        Returns
            ``GitPython.Commit[]``
        """
        return Commit.find_all(self, "%s..%s" % (frm, to)).reverse()

    def commits_since(self, start = 'master', since = '1970-01-01'):
        """
        The Commits objects that are newer than the specified date.
        Commits are returned in chronological order.

        ``start``
            is the branch/commit name (default 'master')

        ``since``
            is a string represeting a date/time

        Returns
            ``GitPython.Commit[]``
        """
        options = {'since': since}

        return Commit.find_all(self, start, **options)

    def commit_count(self, start = 'master'):
        """
        The number of commits reachable by the given branch/commit

        ``start``
            is the branch/commit name (default 'master')

        Returns
            int
        """
        return Commit.count(self, start)

    def commit(self, id):
        """
        The Commit object for the specified id

        ``id``
            is the SHA1 identifier of the commit

        Returns
            GitPython.Commit
        """
        options = {'max_count': 1}

        commits = Commit.find_all(self, id, **options)

        if not commits:
            raise ValueError, 'Invalid identifier %s' % id
        return commits[0]

    def commit_deltas_from(self, other_repo, ref = 'master', other_ref = 'master'):
        """
        Returns a list of commits that is in ``other_repo`` but not in self

        Returns 
            ``GitPython.Commit[]``
        """
        repo_refs = self.git.rev_list(ref).strip().splitlines()
        other_repo_refs = other_repo.git.rev_list(other_ref).strip().splitlines()

        diff_refs = list(set(other_repo_refs) - set(repo_refs))
        return map(lambda ref: Commit.find_all(other_repo, ref, **{'max_count': 1}[0]), diff_refs)

    def tree(self, treeish = 'master', paths = []):
        """
        The Tree object for the given treeish reference

        ``treeish``
            is the reference (default 'master')
        ``paths``
            is an optional Array of directory paths to restrict the tree (deafult [])

        Examples::

          repo.tree('master', ['lib/'])


        Returns
            ``GitPython.Tree``
        """
        return Tree.construct(self, treeish, paths)

    def blob(self, id):
        """
        The Blob object for the given id

        ``id``
            is the SHA1 id of the blob

        Returns
            ``GitPython.Blob``
        """
        return Blob(self, **{'id': id})

    def log(self, commit = 'master', path = None, **kwargs):
        """
        The commit log for a treeish

        Returns
            ``GitPython.Commit[]``
        """
        options = {'pretty': 'raw'}
        options.update(kwargs)
        if path:
            arg = [commit, '--', path]
        else:
            arg = [commit]
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
            ``GitPython.Diff[]``
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

            GitPython.Repo.init_bare('/var/git/myrepo.git')

        Returns
            ``GitPython.Repo`` (the newly created repo)
        """
        split = os.path.split(path)
        if split[-1] == '.git' or os.path.split(split[0])[-1] == '.git':
            gitpath = path
        else:
            gitpath = os.path.join(path, '.git')

        if mkdir and not os.path.exists(gitpath):
            os.makedirs(gitpath, 0755)

        git = Git(gitpath)
        output = git.init(**kwargs)
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
            ``GitPython.Repo`` (the newly forked repo)
        """
        options = {'bare': True}
        options.update(kwargs)
        self.git.clone(self.path, path, **options)
        return Repo(path)

    def archive_tar(self, treeish = 'master', prefix = None):
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

    def archive_tar_gz(self, treeish = 'master', prefix = None):
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
        self.git.archive(treeish, "| gzip", **kwargs)

    def enable_daemon_serve(self):
        """
        Enable git-daemon serving of this repository by writing the
        git-daemon-export-ok file to its git directory

        Returns
            None
        """
        if self.bare:
            touch(os.path.join(self.path, DAEMON_EXPORT_FILE))
        else:
            touch(os.path.join(self.path, '.git', DAEMON_EXPORT_FILE))

    def disable_daemon_serve(self):
        """
        Disable git-daemon serving of this repository by ensuring there is no
        git-daemon-export-ok file in its git directory

        Returns
            None
        """
        if self.bare:
            return os.remove(os.path.join(self.path, DAEMON_EXPORT_FILE))
        else:
            return os.remove(os.path.join(self.path, '.git', DAEMON_EXPORT_FILE))

    def _get_alternates(self):
        """
        The list of alternates for this repo

        Returns
            list[str] (pathnames of alternates)
        """
        alternates_path = os.path.join(self.path, *['objects', 'info', 'alternates'])

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
            os.remove(os.path.join(self.path, *['objects', 'info', 'alternates']))
        else:
            try:
                f = open(os.path.join(self.path, *['objects', 'info', 'alternates']), 'w')
                f.write("\n".join(alts))
            finally:
                f.close()

    alternates = property(_get_alternates, _set_alternates)

    def __repr__(self):
        return '<GitPython.Repo "%s">' % self.path
