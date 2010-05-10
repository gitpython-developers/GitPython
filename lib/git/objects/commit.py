# commit.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.utils import Iterable
import git.diff as diff
import git.stats as stats
from tree import Tree
import base
import utils
import tempfile
import os

class Commit(base.Object, Iterable, diff.Diffable, utils.Traversable):
    """
    Wraps a git Commit object.
    
    This class will act lazily on some of its attributes and will query the 
    value on demand only if it involves calling the git binary.
    """
    
    # object configuration 
    type = "commit"
    __slots__ = ("tree",
                 "author", "authored_date", "author_tz_offset",
                 "committer", "committed_date", "committer_tz_offset",
                 "message", "parents")
    _id_attribute_ = "sha"
    
    def __init__(self, repo, sha, tree=None, author=None, authored_date=None, author_tz_offset=None,
                 committer=None, committed_date=None, committer_tz_offset=None, message=None, parents=None):
        """
        Instantiate a new Commit. All keyword arguments taking None as default will 
        be implicitly set if id names a valid sha. 
        
        The parameter documentation indicates the type of the argument after a colon ':'.

        ``sha``
            is the sha id of the commit or a ref

        ``parents`` : tuple( Commit, ... )
            is a tuple of commit ids or actual Commits

        ``tree`` : Tree
            is the corresponding tree id or an actual Tree

        ``author`` : Actor
            is the author string ( will be implicitly converted into an Actor object )

        ``authored_date`` : int_seconds_since_epoch
            is the authored DateTime - use time.gmtime() to convert it into a 
            different format

        ``author_tz_offset``: int_seconds_west_of_utc
           is the timezone that the authored_date is in

        ``committer`` : Actor
            is the committer string

        ``committed_date`` : int_seconds_since_epoch
            is the committed DateTime - use time.gmtime() to convert it into a 
            different format

        ``committer_tz_offset``: int_seconds_west_of_utc
           is the timezone that the authored_date is in

        ``message`` : string
            is the commit message

        Returns
            git.Commit
        """
        super(Commit,self).__init__(repo, sha)
        self._set_self_from_args_(locals())

        if parents is not None:
            self.parents = tuple( self.__class__(repo, p) for p in parents )
        # END for each parent to convert
            
        if self.sha and tree is not None:
            self.tree = Tree(repo, tree, path='')
        # END id to tree conversion
        
    @classmethod
    def _get_intermediate_items(cls, commit):
        return commit.parents

    def _set_cache_(self, attr):
        """
        Called by LazyMixin superclass when the given uninitialized member needs 
        to be set.
        We set all values at once.
        """
        if attr in Commit.__slots__:
            # prepare our data lines to match rev-list
            data_lines = self.data.splitlines()
            data_lines.insert(0, "commit %s" % self.sha)
            temp = self._iter_from_process_or_stream(self.repo, iter(data_lines), False).next()
            self.parents = temp.parents
            self.tree = temp.tree
            self.author = temp.author
            self.authored_date = temp.authored_date
            self.author_tz_offset = temp.author_tz_offset
            self.committer = temp.committer
            self.committed_date = temp.committed_date
            self.committer_tz_offset = temp.committer_tz_offset
            self.message = temp.message
        else:
            super(Commit, self)._set_cache_(attr)

    @property
    def summary(self):
        """
        Returns
            First line of the commit message.
        """
        return self.message.split('\n', 1)[0]
        
    def count(self, paths='', **kwargs):
        """
        Count the number of commits reachable from this commit

        ``paths``
            is an optinal path or a list of paths restricting the return value 
            to commits actually containing the paths

        ``kwargs``
            Additional options to be passed to git-rev-list. They must not alter
            the ouput style of the command, or parsing will yield incorrect results
        Returns
            int
        """
        # yes, it makes a difference whether empty paths are given or not in our case
        # as the empty paths version will ignore merge commits for some reason.
        if paths:
            return len(self.repo.git.rev_list(self.sha, '--', paths, **kwargs).splitlines())
        else:
            return len(self.repo.git.rev_list(self.sha, **kwargs).splitlines())
        

    @property
    def name_rev(self):
        """
        Returns
            String describing the commits hex sha based on the closest Reference.
            Mostly useful for UI purposes
        """
        return self.repo.git.name_rev(self)

    @classmethod
    def iter_items(cls, repo, rev, paths='', **kwargs):
        """
        Find all commits matching the given criteria.

        ``repo``
            is the Repo

        ``rev``
            revision specifier, see git-rev-parse for viable options

        ``paths``
            is an optinal path or list of paths, if set only Commits that include the path 
            or paths will be considered

        ``kwargs``
            optional keyword arguments to git rev-list where
            ``max_count`` is the maximum number of commits to fetch
            ``skip`` is the number of commits to skip
            ``since`` all commits since i.e. '1970-01-01'

        Returns
            iterator yielding Commit items
        """
        options = {'pretty': 'raw', 'as_process' : True }
        options.update(kwargs)
        
        args = list()
        if paths:
            args.extend(('--', paths))
        # END if paths

        proc = repo.git.rev_list(rev, args, **options)
        return cls._iter_from_process_or_stream(repo, proc, True)
        
    def iter_parents(self, paths='', **kwargs):
        """
        Iterate _all_ parents of this commit.
        
        ``paths``
            Optional path or list of paths limiting the Commits to those that 
            contain at least one of the paths
        
        ``kwargs``
            All arguments allowed by git-rev-list
            
        Return:
            Iterator yielding Commit objects which are parents of self
        """
        # skip ourselves
        skip = kwargs.get("skip", 1)
        if skip == 0:   # skip ourselves 
            skip = 1
        kwargs['skip'] = skip
        
        return self.iter_items( self.repo, self, paths, **kwargs )

    @property
    def stats(self):
        """
        Create a git stat from changes between this commit and its first parent 
        or from all changes done if this is the very first commit.
        
        Return
            git.Stats
        """
        if not self.parents:
            text = self.repo.git.diff_tree(self.sha, '--', numstat=True, root=True)
            text2 = ""
            for line in text.splitlines()[1:]:
                (insertions, deletions, filename) = line.split("\t")
                text2 += "%s\t%s\t%s\n" % (insertions, deletions, filename)
            text = text2
        else:
            text = self.repo.git.diff(self.parents[0].sha, self.sha, '--', numstat=True)
        return stats.Stats._list_from_string(self.repo, text)

    @classmethod
    def _iter_from_process_or_stream(cls, repo, proc_or_stream, from_rev_list):
        """
        Parse out commit information into a list of Commit objects

        ``repo``
            is the Repo

        ``proc``
            git-rev-list process instance (raw format)

        ``from_rev_list``
            If True, the stream was created by rev-list in which case we parse 
            the message differently
        Returns
            iterator returning Commit objects
        """
        stream = proc_or_stream
        if not hasattr(stream,'next'):
            stream = proc_or_stream.stdout
            
        for line in stream:
            commit_tokens = line.split() 
            id = commit_tokens[1]
            assert commit_tokens[0] == "commit"
            tree = stream.next().split()[1]

            parents = []
            next_line = None
            for parent_line in stream:
                if not parent_line.startswith('parent'):
                    next_line = parent_line
                    break
                # END abort reading parents
                parents.append(parent_line.split()[-1])
            # END for each parent line
            
            author, authored_date, author_tz_offset = utils.parse_actor_and_date(next_line)
            committer, committed_date, committer_tz_offset = utils.parse_actor_and_date(stream.next())
            
            # empty line
            stream.next()
            
            message_lines = []
            if from_rev_list:
                for msg_line in stream:
                    if not msg_line.startswith('    '):
                        # and forget about this empty marker
                        break
                    # END abort message reading 
                    # strip leading 4 spaces
                    message_lines.append(msg_line[4:])
                # END while there are message lines
            else:
                # a stream from our data simply gives us the plain message
                for msg_line in stream:
                    message_lines.append(msg_line)
            # END message parsing
            message = '\n'.join(message_lines)
            
            yield Commit(repo, id, parents=tuple(parents), tree=tree,
                         author=author, authored_date=authored_date, author_tz_offset=author_tz_offset,
                         committer=committer, committed_date=committed_date, committer_tz_offset=committer_tz_offset,
                         message=message)
        # END for each line in stream
        
        
    @classmethod
    def create_from_tree(cls, repo, tree, message, parent_commits=None, head=False):
        """
        Commit the given tree, creating a commit object.
        
        ``repo``
            is the Repo
            
        ``tree``
            Sha of a tree or a tree object to become the tree of the new commit
        
        ``message``
            Commit message. It may be an empty string if no message is provided.
            It will be converted to a string in any case.
            
        ``parent_commits``
            Optional Commit objects to use as parents for the new commit.
            If empty list, the commit will have no parents at all and become 
            a root commit.
            If None , the current head commit will be the parent of the 
            new commit object
            
        ``head``
            If True, the HEAD will be advanced to the new commit automatically.
            Else the HEAD will remain pointing on the previous commit. This could 
            lead to undesired results when diffing files.
            
        Returns
            Commit object representing the new commit
            
        Note:
            Additional information about hte committer and Author are taken from the
            environment or from the git configuration, see git-commit-tree for 
            more information
        """
        parents = parent_commits
        if parent_commits is None:
            try:
                parent_commits = [ repo.head.commit ]
            except ValueError:
                # empty repositories have no head commit
                parent_commits = list()
            # END handle parent commits
        # END if parent commits are unset
        
        parent_args = [ ("-p", str(commit)) for commit in parent_commits ]
        
        # create message stream
        tmp_file_path = tempfile.mktemp()
        fp = open(tmp_file_path,"wb")
        fp.write(str(message))
        fp.close()
        fp = open(tmp_file_path,"rb")
        fp.seek(0)
        
        try:
            # write the current index as tree
            commit_sha = repo.git.commit_tree(tree, parent_args, istream=fp)
            new_commit = cls(repo, commit_sha)
            
            if head:
                try:
                    repo.head.commit = new_commit
                except ValueError:
                    # head is not yet set to the ref our HEAD points to.
                    import git.refs
                    master = git.refs.Head.create(repo, repo.head.ref, commit=new_commit)
                    repo.head.reference = master
                # END handle empty repositories
            # END advance head handling 
            
            return new_commit
        finally:
            fp.close()
            os.remove(tmp_file_path)
        
    def __str__(self):
        """ Convert commit to string which is SHA1 """
        return self.sha

    def __repr__(self):
        return '<git.Commit "%s">' % self.sha

