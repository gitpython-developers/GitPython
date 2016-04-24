# remote.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

# Module implementing a remote object allowing easy access to git remotes
import re
import os

from .exc import GitCommandError
from .config import (
    SectionConstraint,
    cp,
)
from .refs import (
    Head,
    Reference,
    RemoteReference,
    SymbolicReference,
    TagReference
)


from git.util import (
    LazyMixin,
    Iterable,
    IterableList,
    RemoteProgress
)
from git.util import (
    join_path,
    finalize_process
)
from git.cmd import handle_process_output
from gitdb.util import join
from git.compat import defenc


__all__ = ('RemoteProgress', 'PushInfo', 'FetchInfo', 'Remote')

#{ Utilities


def add_progress(kwargs, git, progress):
    """Add the --progress flag to the given kwargs dict if supported by the
    git command. If the actual progress in the given progress instance is not
    given, we do not request any progress
    :return: possibly altered kwargs"""
    if progress is not None:
        v = git.version_info
        if v[0] > 1 or v[1] > 7 or v[2] > 0 or v[3] > 3:
            kwargs['progress'] = True
        # END handle --progress
    # END handle progress
    return kwargs

#} END utilities


class PushInfo(object):

    """
    Carries information about the result of a push operation of a single head::

        info = remote.push()[0]
        info.flags          # bitflags providing more information about the result
        info.local_ref      # Reference pointing to the local reference that was pushed
                            # It is None if the ref was deleted.
        info.remote_ref_string # path to the remote reference located on the remote side
        info.remote_ref # Remote Reference on the local side corresponding to
                        # the remote_ref_string. It can be a TagReference as well.
        info.old_commit # commit at which the remote_ref was standing before we pushed
                        # it to local_ref.commit. Will be None if an error was indicated
        info.summary    # summary line providing human readable english text about the push
        """
    __slots__ = ('local_ref', 'remote_ref_string', 'flags', 'old_commit', '_remote', 'summary')

    NEW_TAG, NEW_HEAD, NO_MATCH, REJECTED, REMOTE_REJECTED, REMOTE_FAILURE, DELETED, \
        FORCED_UPDATE, FAST_FORWARD, UP_TO_DATE, ERROR = [1 << x for x in range(11)]

    _flag_map = {'X': NO_MATCH,
                 '-': DELETED,
                 '*': 0,
                 '+': FORCED_UPDATE,
                 ' ': FAST_FORWARD,
                 '=': UP_TO_DATE,
                 '!': ERROR}

    def __init__(self, flags, local_ref, remote_ref_string, remote, old_commit=None,
                 summary=''):
        """ Initialize a new instance """
        self.flags = flags
        self.local_ref = local_ref
        self.remote_ref_string = remote_ref_string
        self._remote = remote
        self.old_commit = old_commit
        self.summary = summary

    @property
    def remote_ref(self):
        """
        :return:
            Remote Reference or TagReference in the local repository corresponding
            to the remote_ref_string kept in this instance."""
        # translate heads to a local remote, tags stay as they are
        if self.remote_ref_string.startswith("refs/tags"):
            return TagReference(self._remote.repo, self.remote_ref_string)
        elif self.remote_ref_string.startswith("refs/heads"):
            remote_ref = Reference(self._remote.repo, self.remote_ref_string)
            return RemoteReference(self._remote.repo, "refs/remotes/%s/%s" % (str(self._remote), remote_ref.name))
        else:
            raise ValueError("Could not handle remote ref: %r" % self.remote_ref_string)
        # END

    @classmethod
    def _from_line(cls, remote, line):
        """Create a new PushInfo instance as parsed from line which is expected to be like
            refs/heads/master:refs/heads/master 05d2687..1d0568e as bytes"""
        control_character, from_to, summary = line.split('\t', 3)
        flags = 0

        # control character handling
        try:
            flags |= cls._flag_map[control_character]
        except KeyError:
            raise ValueError("Control character %r unknown as parsed from line %r" % (control_character, line))
        # END handle control character

        # from_to handling
        from_ref_string, to_ref_string = from_to.split(':')
        if flags & cls.DELETED:
            from_ref = None
        else:
            from_ref = Reference.from_path(remote.repo, from_ref_string)

        # commit handling, could be message or commit info
        old_commit = None
        if summary.startswith('['):
            if "[rejected]" in summary:
                flags |= cls.REJECTED
            elif "[remote rejected]" in summary:
                flags |= cls.REMOTE_REJECTED
            elif "[remote failure]" in summary:
                flags |= cls.REMOTE_FAILURE
            elif "[no match]" in summary:
                flags |= cls.ERROR
            elif "[new tag]" in summary:
                flags |= cls.NEW_TAG
            elif "[new branch]" in summary:
                flags |= cls.NEW_HEAD
            # uptodate encoded in control character
        else:
            # fast-forward or forced update - was encoded in control character,
            # but we parse the old and new commit
            split_token = "..."
            if control_character == " ":
                split_token = ".."
            old_sha, new_sha = summary.split(' ')[0].split(split_token)
            # have to use constructor here as the sha usually is abbreviated
            old_commit = remote.repo.commit(old_sha)
        # END message handling

        return PushInfo(flags, from_ref, to_ref_string, remote, old_commit, summary)


class FetchInfo(object):

    """
    Carries information about the results of a fetch operation of a single head::

     info = remote.fetch()[0]
     info.ref           # Symbolic Reference or RemoteReference to the changed
                        # remote head or FETCH_HEAD
     info.flags         # additional flags to be & with enumeration members,
                        # i.e. info.flags & info.REJECTED
                        # is 0 if ref is SymbolicReference
     info.note          # additional notes given by git-fetch intended for the user
     info.old_commit    # if info.flags & info.FORCED_UPDATE|info.FAST_FORWARD,
                        # field is set to the previous location of ref, otherwise None
     info.remote_ref_path # The path from which we fetched on the remote. It's the remote's version of our info.ref
    """
    __slots__ = ('ref', 'old_commit', 'flags', 'note', 'remote_ref_path')

    NEW_TAG, NEW_HEAD, HEAD_UPTODATE, TAG_UPDATE, REJECTED, FORCED_UPDATE, \
        FAST_FORWARD, ERROR = [1 << x for x in range(8)]

    re_fetch_result = re.compile("^\s*(.) (\[?[\w\s\.$@]+\]?)\s+(.+) -> ([/\w_\+\.\-$@#]+)(    \(.*\)?$)?")

    _flag_map = {'!': ERROR,
                 '+': FORCED_UPDATE,
                 '-': TAG_UPDATE,
                 '*': 0,
                 '=': HEAD_UPTODATE,
                 ' ': FAST_FORWARD}

    def __init__(self, ref, flags, note='', old_commit=None, remote_ref_path=None):
        """
        Initialize a new instance
        """
        self.ref = ref
        self.flags = flags
        self.note = note
        self.old_commit = old_commit
        self.remote_ref_path = remote_ref_path

    def __str__(self):
        return self.name

    @property
    def name(self):
        """:return: Name of our remote ref"""
        return self.ref.name

    @property
    def commit(self):
        """:return: Commit of our remote ref"""
        return self.ref.commit

    @classmethod
    def _from_line(cls, repo, line, fetch_line):
        """Parse information from the given line as returned by git-fetch -v
        and return a new FetchInfo object representing this information.

        We can handle a line as follows
        "%c %-*s %-*s -> %s%s"

        Where c is either ' ', !, +, -, *, or =
        ! means error
        + means success forcing update
        - means a tag was updated
        * means birth of new branch or tag
        = means the head was up to date ( and not moved )
        ' ' means a fast-forward

        fetch line is the corresponding line from FETCH_HEAD, like
        acb0fa8b94ef421ad60c8507b634759a472cd56c    not-for-merge   branch '0.1.7RC' of /tmp/tmpya0vairemote_repo"""
        match = cls.re_fetch_result.match(line)
        if match is None:
            raise ValueError("Failed to parse line: %r" % line)

        # parse lines
        control_character, operation, local_remote_ref, remote_local_ref, note = match.groups()
        try:
            new_hex_sha, fetch_operation, fetch_note = fetch_line.split("\t")
            ref_type_name, fetch_note = fetch_note.split(' ', 1)
        except ValueError:  # unpack error
            raise ValueError("Failed to parse FETCH_HEAD line: %r" % fetch_line)

        # parse flags from control_character
        flags = 0
        try:
            flags |= cls._flag_map[control_character]
        except KeyError:
            raise ValueError("Control character %r unknown as parsed from line %r" % (control_character, line))
        # END control char exception hanlding

        # parse operation string for more info - makes no sense for symbolic refs, but we parse it anyway
        old_commit = None
        is_tag_operation = False
        if 'rejected' in operation:
            flags |= cls.REJECTED
        if 'new tag' in operation:
            flags |= cls.NEW_TAG
            is_tag_operation = True
        if 'tag update' in operation:
            flags |= cls.TAG_UPDATE
            is_tag_operation = True
        if 'new branch' in operation:
            flags |= cls.NEW_HEAD
        if '...' in operation or '..' in operation:
            split_token = '...'
            if control_character == ' ':
                split_token = split_token[:-1]
            old_commit = repo.rev_parse(operation.split(split_token)[0])
        # END handle refspec

        # handle FETCH_HEAD and figure out ref type
        # If we do not specify a target branch like master:refs/remotes/origin/master,
        # the fetch result is stored in FETCH_HEAD which destroys the rule we usually
        # have. In that case we use a symbolic reference which is detached
        ref_type = None
        if remote_local_ref == "FETCH_HEAD":
            ref_type = SymbolicReference
        elif ref_type_name == "tag" or is_tag_operation:
            # the ref_type_name can be branch, whereas we are still seeing a tag operation. It happens during
            # testing, which is based on actual git operations
            ref_type = TagReference
        elif ref_type_name in ("remote-tracking", "branch"):
            # note: remote-tracking is just the first part of the 'remote-tracking branch' token.
            # We don't parse it correctly, but its enough to know what to do, and its new in git 1.7something
            ref_type = RemoteReference
        elif '/' in ref_type_name:
            # If the fetch spec look something like this '+refs/pull/*:refs/heads/pull/*', and is thus pretty
            # much anything the user wants, we will have trouble to determine what's going on
            # For now, we assume the local ref is a Head
            ref_type = Head
        else:
            raise TypeError("Cannot handle reference type: %r" % ref_type_name)
        # END handle ref type

        # create ref instance
        if ref_type is SymbolicReference:
            remote_local_ref = ref_type(repo, "FETCH_HEAD")
        else:
            # determine prefix. Tags are usually pulled into refs/tags, they may have subdirectories.
            # It is not clear sometimes where exactly the item is, unless we have an absolute path as indicated
            # by the 'ref/' prefix. Otherwise even a tag could be in refs/remotes, which is when it will have the
            # 'tags/' subdirectory in its path.
            # We don't want to test for actual existence, but try to figure everything out analytically.
            ref_path = None
            remote_local_ref = remote_local_ref.strip()
            if remote_local_ref.startswith(Reference._common_path_default + "/"):
                # always use actual type if we get absolute paths
                # Will always be the case if something is fetched outside of refs/remotes (if its not a tag)
                ref_path = remote_local_ref
                if ref_type is not TagReference and not \
                   remote_local_ref.startswith(RemoteReference._common_path_default + "/"):
                    ref_type = Reference
                # END downgrade remote reference
            elif ref_type is TagReference and 'tags/' in remote_local_ref:
                # even though its a tag, it is located in refs/remotes
                ref_path = join_path(RemoteReference._common_path_default, remote_local_ref)
            else:
                ref_path = join_path(ref_type._common_path_default, remote_local_ref)
            # END obtain refpath

            # even though the path could be within the git conventions, we make
            # sure we respect whatever the user wanted, and disabled path checking
            remote_local_ref = ref_type(repo, ref_path, check_path=False)
        # END create ref instance

        note = (note and note.strip()) or ''

        return cls(remote_local_ref, flags, note, old_commit, local_remote_ref)


class Remote(LazyMixin, Iterable):

    """Provides easy read and write access to a git remote.

    Everything not part of this interface is considered an option for the current
    remote, allowing constructs like remote.pushurl to query the pushurl.

    NOTE: When querying configuration, the configuration accessor will be cached
    to speed up subsequent accesses."""

    __slots__ = ("repo", "name", "_config_reader")
    _id_attribute_ = "name"

    def __init__(self, repo, name):
        """Initialize a remote instance

        :param repo: The repository we are a remote of
        :param name: the name of the remote, i.e. 'origin'"""
        self.repo = repo
        self.name = name

        if os.name == 'nt':
            # some oddity: on windows, python 2.5, it for some reason does not realize
            # that it has the config_writer property, but instead calls __getattr__
            # which will not yield the expected results. 'pinging' the members
            # with a dir call creates the config_writer property that we require
            # ... bugs like these make me wonder whether python really wants to be used
            # for production. It doesn't happen on linux though.
            dir(self)
        # END windows special handling

    def __getattr__(self, attr):
        """Allows to call this instance like
        remote.special( \*args, \*\*kwargs) to call git-remote special self.name"""
        if attr == "_config_reader":
            return super(Remote, self).__getattr__(attr)

        # sometimes, probably due to a bug in python itself, we are being called
        # even though a slot of the same name exists
        try:
            return self._config_reader.get(attr)
        except cp.NoOptionError:
            return super(Remote, self).__getattr__(attr)
        # END handle exception

    def _config_section_name(self):
        return 'remote "%s"' % self.name

    def _set_cache_(self, attr):
        if attr == "_config_reader":
            # NOTE: This is cached as __getattr__ is overridden to return remote config values implicitly, such as
            # in print(r.pushurl)
            self._config_reader = SectionConstraint(self.repo.config_reader("repository"), self._config_section_name())
        else:
            super(Remote, self)._set_cache_(attr)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<git.%s "%s">' % (self.__class__.__name__, self.name)

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.name)

    def exists(self):
        """
        :return: True if this is a valid, existing remote.
            Valid remotes have an entry in the repository's configuration"""
        try:
            self.config_reader.get('url')
            return True
        except cp.NoOptionError:
            # we have the section at least ...
            return True
        except cp.NoSectionError:
            return False
        # end

    @classmethod
    def iter_items(cls, repo):
        """:return: Iterator yielding Remote objects of the given repository"""
        for section in repo.config_reader("repository").sections():
            if not section.startswith('remote'):
                continue
            lbound = section.find('"')
            rbound = section.rfind('"')
            if lbound == -1 or rbound == -1:
                raise ValueError("Remote-Section has invalid format: %r" % section)
            yield Remote(repo, section[lbound + 1:rbound])
        # END for each configuration section

    @property
    def refs(self):
        """
        :return:
            IterableList of RemoteReference objects. It is prefixed, allowing
            you to omit the remote path portion, i.e.::
            remote.refs.master # yields RemoteReference('/refs/remotes/origin/master')"""
        out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
        out_refs.extend(RemoteReference.list_items(self.repo, remote=self.name))
        assert out_refs, "Remote %s did not have any references" % self.name
        return out_refs

    @property
    def stale_refs(self):
        """
        :return:
            IterableList RemoteReference objects that do not have a corresponding
            head in the remote reference anymore as they have been deleted on the
            remote side, but are still available locally.

            The IterableList is prefixed, hence the 'origin' must be omitted. See
            'refs' property for an example.

            To make things more complicated, it can be possble for the list to include
            other kinds of references, for example, tag references, if these are stale
            as well. This is a fix for the issue described here:
            https://github.com/gitpython-developers/GitPython/issues/260
            """
        out_refs = IterableList(RemoteReference._id_attribute_, "%s/" % self.name)
        for line in self.repo.git.remote("prune", "--dry-run", self).splitlines()[2:]:
            # expecting
            # * [would prune] origin/new_branch
            token = " * [would prune] "
            if not line.startswith(token):
                raise ValueError("Could not parse git-remote prune result: %r" % line)
            ref_name = line.replace(token, "")
            # sometimes, paths start with a full ref name, like refs/tags/foo, see #260
            if ref_name.startswith(Reference._common_path_default + '/'):
                out_refs.append(SymbolicReference.from_path(self.repo, ref_name))
            else:
                fqhn = "%s/%s" % (RemoteReference._common_path_default, ref_name)
                out_refs.append(RemoteReference(self.repo, fqhn))
            # end special case handlin
        # END for each line
        return out_refs

    @classmethod
    def create(cls, repo, name, url, **kwargs):
        """Create a new remote to the given repository
        :param repo: Repository instance that is to receive the new remote
        :param name: Desired name of the remote
        :param url: URL which corresponds to the remote's name
        :param kwargs: Additional arguments to be passed to the git-remote add command
        :return: New Remote instance
        :raise GitCommandError: in case an origin with that name already exists"""
        scmd = 'add'
        kwargs['insert_kwargs_after'] = scmd
        repo.git.remote(scmd, name, url, **kwargs)
        return cls(repo, name)

    # add is an alias
    add = create

    @classmethod
    def remove(cls, repo, name):
        """Remove the remote with the given name
        :return: the passed remote name to remove
        """
        repo.git.remote("rm", name)
        if isinstance(name, cls):
            name._clear_cache()
        return name

    # alias
    rm = remove

    def rename(self, new_name):
        """Rename self to the given new_name
        :return: self """
        if self.name == new_name:
            return self

        self.repo.git.remote("rename", self.name, new_name)
        self.name = new_name
        self._clear_cache()

        return self

    def update(self, **kwargs):
        """Fetch all changes for this remote, including new branches which will
        be forced in ( in case your local remote branch is not part the new remote branches
        ancestry anymore ).

        :param kwargs:
            Additional arguments passed to git-remote update

        :return: self """
        scmd = 'update'
        kwargs['insert_kwargs_after'] = scmd
        self.repo.git.remote(scmd, self.name, **kwargs)
        return self

    def _get_fetch_info_from_stderr(self, proc, progress):
        # skip first line as it is some remote info we are not interested in
        output = IterableList('name')

        # lines which are no progress are fetch info lines
        # this also waits for the command to finish
        # Skip some progress lines that don't provide relevant information
        fetch_info_lines = list()
        # Basically we want all fetch info lines which appear to be in regular form, and thus have a
        # command character. Everything else we ignore,
        cmds = set(PushInfo._flag_map.keys()) & set(FetchInfo._flag_map.keys())

        progress_handler = progress.new_message_handler()

        for line in proc.stderr.readlines():
            line = line.decode(defenc)
            for pline in progress_handler(line):
                if line.startswith('fatal:') or line.startswith('error:'):
                    raise GitCommandError(("Error when fetching: %s" % line,), 2)
                # END handle special messages
                for cmd in cmds:
                    if len(line) > 1 and line[0] == ' ' and line[1] == cmd:
                        fetch_info_lines.append(line)
                        continue
                    # end find command code
                # end for each comand code we know
            # end for each line progress didn't handle
        # end
        finalize_process(proc)

        # read head information
        fp = open(join(self.repo.git_dir, 'FETCH_HEAD'), 'rb')
        fetch_head_info = [l.decode(defenc) for l in fp.readlines()]
        fp.close()

        # NOTE: We assume to fetch at least enough progress lines to allow matching each fetch head line with it.
        l_fil = len(fetch_info_lines)
        l_fhi = len(fetch_head_info)
        assert l_fil >= l_fhi, "len(%s) <= len(%s)" % (l_fil, l_fhi)

        output.extend(FetchInfo._from_line(self.repo, err_line, fetch_line)
                      for err_line, fetch_line in zip(fetch_info_lines, fetch_head_info))
        return output

    def _get_push_info(self, proc, progress):
        # read progress information from stderr
        # we hope stdout can hold all the data, it should ...
        # read the lines manually as it will use carriage returns between the messages
        # to override the previous one. This is why we read the bytes manually
        progress_handler = progress.new_message_handler()
        output = IterableList('name')

        def stdout_handler(line):
            try:
                output.append(PushInfo._from_line(self, line))
            except ValueError:
                # if an error happens, additional info is given which we cannot parse
                pass
            # END exception handling
        # END for each line

        try:
            handle_process_output(proc, stdout_handler, progress_handler, finalize_process)
        except Exception:
            if len(output) == 0:
                raise
        return output

    def _assert_refspec(self):
        """Turns out we can't deal with remotes if the refspec is missing"""
        config = self.config_reader
        unset = 'placeholder'
        try:
            if config.get_value('fetch', default=unset) is unset:
                msg = "Remote '%s' has no refspec set.\n"
                msg += "You can set it as follows:"
                msg += " 'git config --add \"remote.%s.fetch +refs/heads/*:refs/heads/*\"'." % (self.name, self.name)
                raise AssertionError(msg)
        finally:
            config.release()

    def fetch(self, refspec=None, progress=None, **kwargs):
        """Fetch the latest changes for this remote

        :param refspec:
            A "refspec" is used by fetch and push to describe the mapping
            between remote ref and local ref. They are combined with a colon in
            the format <src>:<dst>, preceded by an optional plus sign, +.
            For example: git fetch $URL refs/heads/master:refs/heads/origin means
            "grab the master branch head from the $URL and store it as my origin
            branch head". And git push $URL refs/heads/master:refs/heads/to-upstream
            means "publish my master branch head as to-upstream branch at $URL".
            See also git-push(1).

            Taken from the git manual

            Fetch supports multiple refspecs (as the
            underlying git-fetch does) - supplying a list rather than a string
            for 'refspec' will make use of this facility.
        :param progress: See 'push' method
        :param kwargs: Additional arguments to be passed to git-fetch
        :return:
            IterableList(FetchInfo, ...) list of FetchInfo instances providing detailed
            information about the fetch results

        :note:
            As fetch does not provide progress information to non-ttys, we cannot make
            it available here unfortunately as in the 'push' method."""
        if refspec is None:
            # No argument refspec, then ensure the repo's config has a fetch refspec.
            self._assert_refspec()
        kwargs = add_progress(kwargs, self.repo.git, progress)
        if isinstance(refspec, list):
            args = refspec
        else:
            args = [refspec]

        proc = self.repo.git.fetch(self, *args, as_process=True, with_stdout=False, v=True,
                                   **kwargs)
        res = self._get_fetch_info_from_stderr(proc, progress or RemoteProgress())
        if hasattr(self.repo.odb, 'update_cache'):
            self.repo.odb.update_cache()
        return res

    def pull(self, refspec=None, progress=None, **kwargs):
        """Pull changes from the given branch, being the same as a fetch followed
        by a merge of branch with your local branch.

        :param refspec: see 'fetch' method
        :param progress: see 'push' method
        :param kwargs: Additional arguments to be passed to git-pull
        :return: Please see 'fetch' method """
        if refspec is None:
            # No argument refspec, then ensure the repo's config has a fetch refspec.
            self._assert_refspec()
        kwargs = add_progress(kwargs, self.repo.git, progress)
        proc = self.repo.git.pull(self, refspec, with_stdout=False, as_process=True, v=True, **kwargs)
        res = self._get_fetch_info_from_stderr(proc, progress or RemoteProgress())
        if hasattr(self.repo.odb, 'update_cache'):
            self.repo.odb.update_cache()
        return res

    def push(self, refspec=None, progress=None, **kwargs):
        """Push changes from source branch in refspec to target branch in refspec.

        :param refspec: see 'fetch' method
        :param progress:
            Instance of type RemoteProgress allowing the caller to receive
            progress information until the method returns.
            If None, progress information will be discarded

        :param kwargs: Additional arguments to be passed to git-push
        :return:
            IterableList(PushInfo, ...) iterable list of PushInfo instances, each
            one informing about an individual head which had been updated on the remote
            side.
            If the push contains rejected heads, these will have the PushInfo.ERROR bit set
            in their flags.
            If the operation fails completely, the length of the returned IterableList will
            be null."""
        kwargs = add_progress(kwargs, self.repo.git, progress)
        proc = self.repo.git.push(self, refspec, porcelain=True, as_process=True, **kwargs)
        return self._get_push_info(proc, progress or RemoteProgress())

    @property
    def config_reader(self):
        """
        :return:
            GitConfigParser compatible object able to read options for only our remote.
            Hence you may simple type config.get("pushurl") to obtain the information"""
        return self._config_reader

    def _clear_cache(self):
        try:
            del(self._config_reader)
        except AttributeError:
            pass
        # END handle exception

    @property
    def config_writer(self):
        """
        :return: GitConfigParser compatible object able to write options for this remote.
        :note:
            You can only own one writer at a time - delete it to release the
            configuration file and make it useable by others.

            To assure consistent results, you should only query options through the
            writer. Once you are done writing, you are free to use the config reader
            once again."""
        writer = self.repo.config_writer()

        # clear our cache to assure we re-read the possibly changed configuration
        self._clear_cache()
        return SectionConstraint(writer, self._config_section_name())
