# index.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
"""
Module containing Index implementation, allowing to perform all kinds of index
manipulations such as querying and merging.
"""
import struct
import binascii
import mmap
import objects
import tempfile
import os
import sys
import stat
import subprocess
import glob
import git.diff as diff

from errors import GitCommandError
from git.objects import Blob, Tree, Object, Commit
from git.utils import SHA1Writer, LazyMixin, ConcurrentWriteOperation, join_path_native


class CheckoutError( Exception ):
    """Thrown if a file could not be checked out from the index as it contained
    changes.

    The .failed_files attribute contains a list of relative paths that failed
    to be checked out as they contained changes that did not exist in the index.

    The .failed_reasons attribute contains a string informing about the actual
    cause of the issue.

    The .valid_files attribute contains a list of relative paths to files that
    were checked out successfully and hence match the version stored in the
    index"""
    def __init__(self, message, failed_files, valid_files, failed_reasons):
        Exception.__init__(self, message)
        self.failed_files = failed_files
        self.failed_reasons = failed_reasons
        self.valid_files = valid_files

    def __str__(self):
        return Exception.__str__(self) + ":%s" % self.failed_files


class _TemporaryFileSwap(object):
    """
    Utility class moving a file to a temporary location within the same directory
    and moving it back on to where on object deletion.
    """
    __slots__ = ("file_path", "tmp_file_path")

    def __init__(self, file_path):
        self.file_path = file_path
        self.tmp_file_path = self.file_path + tempfile.mktemp('','','')
        # it may be that the source does not exist
        try:
            os.rename(self.file_path, self.tmp_file_path)
        except OSError:
            pass

    def __del__(self):
        if os.path.isfile(self.tmp_file_path):
            if os.name == 'nt' and os.path.exists(self.file_path):
                os.remove(self.file_path)
            os.rename(self.tmp_file_path, self.file_path)
        # END temp file exists


class BlobFilter(object):
    """
    Predicate to be used by iter_blobs allowing to filter only return blobs which
    match the given list of directories or files.

    The given paths are given relative to the repository.
    """
    __slots__ = 'paths'

    def __init__(self, paths):
        """
        ``paths``
            tuple or list of paths which are either pointing to directories or
            to files relative to the current repository
        """
        self.paths = paths

    def __call__(self, stage_blob):
        path = stage_blob[1].path
        for p in self.paths:
            if path.startswith(p):
                return True
        # END for each path in filter paths
        return False


class BaseIndexEntry(tuple):
    """
    Small Brother of an index entry which can be created to describe changes
    done to the index in which case plenty of additional information is not requried.

    As the first 4 data members match exactly to the IndexEntry type, methods
    expecting a BaseIndexEntry can also handle full IndexEntries even if they
    use numeric indices for performance reasons.
    """

    def __str__(self):
        return "%o %s %i\t%s" % (self.mode, self.sha, self.stage, self.path)

    @property
    def mode(self):
        """
        File Mode, compatible to stat module constants
        """
        return self[0]

    @property
    def sha(self):
        """
        hex sha of the blob
        """
        return self[1]

    @property
    def stage(self):
        """
        Stage of the entry, either:
            0 = default stage
            1 = stage before a merge or common ancestor entry in case of a 3 way merge
            2 = stage of entries from the 'left' side of the merge
            3 = stage of entries from the right side of the merge
        Note:
            For more information, see http://www.kernel.org/pub/software/scm/git/docs/git-read-tree.html
        """
        return self[2]

    @property
    def path(self):
        return self[3]

    @classmethod
    def from_blob(cls, blob, stage = 0):
        """
        Returns
            Fully equipped BaseIndexEntry at the given stage
        """
        return cls((blob.mode, blob.sha, stage, blob.path))


class IndexEntry(BaseIndexEntry):
    """
    Allows convenient access to IndexEntry data without completely unpacking it.

    Attributes usully accessed often are cached in the tuple whereas others are
    unpacked on demand.

    See the properties for a mapping between names and tuple indices.
    """
    @property
    def ctime(self):
        """
        Returns
            Tuple(int_time_seconds_since_epoch, int_nano_seconds) of the
            file's creation time
        """
        return struct.unpack(">LL", self[4])

    @property
    def mtime(self):
        """
        See ctime property, but returns modification time
        """
        return struct.unpack(">LL", self[5])

    @property
    def dev(self):
        """
        Device ID
        """
        return self[6]

    @property
    def inode(self):
        """
        Inode ID
        """
        return self[7]

    @property
    def uid(self):
        """
        User ID
        """
        return self[8]

    @property
    def gid(self):
        """
        Group ID
        """
        return self[9]

    @property
    def size(self):
        """
        Uncompressed size of the blob

        Note
            Will be 0 if the stage is not 0 ( hence it is an unmerged entry )
        """
        return self[10]

    @classmethod
    def from_base(cls, base):
        """
        Returns
            Minimal entry as created from the given BaseIndexEntry instance.
            Missing values will be set to null-like values

        ``base``
            Instance of type BaseIndexEntry
        """
        time = struct.pack(">LL", 0, 0)
        return IndexEntry((base.mode, base.sha, base.stage, base.path, time, time, 0, 0, 0, 0, 0))

    @classmethod
    def from_blob(cls, blob):
        """
        Returns
            Minimal entry resembling the given blob objecft
        """
        time = struct.pack(">LL", 0, 0)
        return IndexEntry((blob.mode, blob.sha, 0, blob.path, time, time, 0, 0, 0, 0, blob.size))


def clear_cache(func):
    """
    Decorator for functions that alter the index using the git command. This would
    invalidate our possibly existing entries dictionary which is why it must be
    deleted to allow it to be lazily reread later.

    Note
        This decorator will not be required once all functions are implemented
        natively which in fact is possible, but probably not feasible performance wise.
    """
    def clear_cache_if_not_raised(self, *args, **kwargs):
        rval = func(self, *args, **kwargs)
        self._delete_entries_cache()
        return rval

    # END wrapper method
    clear_cache_if_not_raised.__name__ = func.__name__
    return clear_cache_if_not_raised


def default_index(func):
    """
    Decorator assuring the wrapped method may only run if we are the default
    repository index. This is as we rely on git commands that operate
    on that index only.
    """
    def check_default_index(self, *args, **kwargs):
        if self._file_path != self._index_path():
            raise AssertionError( "Cannot call %r on indices that do not represent the default git index" % func.__name__ )
        return func(self, *args, **kwargs)
    # END wrpaper method

    check_default_index.__name__ = func.__name__
    return check_default_index


class IndexFile(LazyMixin, diff.Diffable):
    """
    Implements an Index that can be manipulated using a native implementation in
    order to save git command function calls wherever possible.

    It provides custom merging facilities allowing to merge without actually changing
    your index or your working tree. This way you can perform own test-merges based
    on the index only without having to deal with the working copy. This is useful
    in case of partial working trees.

    ``Entries``
    The index contains an entries dict whose keys are tuples of type IndexEntry
    to facilitate access.

    You may read the entries dict or manipulate it using IndexEntry instance, i.e.::
        index.entries[index.get_entries_key(index_entry_instance)] = index_entry_instance
    Otherwise changes to it will be lost when changing the index using its methods.
    """
    __slots__ = ( "repo", "version", "entries", "_extension_data", "_file_path" )
    _VERSION = 2            # latest version we support
    S_IFGITLINK = 0160000

    def __init__(self, repo, file_path=None):
        """
        Initialize this Index instance, optionally from the given ``file_path``.
        If no file_path is given, we will be created from the current index file.

        If a stream is not given, the stream will be initialized from the current
        repository's index on demand.
        """
        self.repo = repo
        self.version = self._VERSION
        self._extension_data = ''
        self._file_path = file_path or self._index_path()

    def _set_cache_(self, attr):
        if attr == "entries":
            # read the current index
            # try memory map for speed
            try:
                fp = open(self._file_path, "rb")
            except IOError:
                # in new repositories, there may be no index, which means we are empty
                self.entries = dict()
                return
            # END exception handling

            stream = fp
            try:
                raise Exception()
                stream = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            except Exception:
                pass
            # END memory mapping

            try:
                self._read_from_stream(stream)
            finally:
                pass
                # make sure we close the stream ( possibly an mmap )
                # and the file
                #stream.close()
                #if stream is not fp:
                #   fp.close()
            # END read from default index on demand
        else:
            super(IndexFile, self)._set_cache_(attr)

    def _index_path(self):
        return join_path_native(self.repo.git_dir, "index")


    @property
    def path(self):
        """
        Returns
            Path to the index file we are representing
        """
        return self._file_path

    def _delete_entries_cache(self):
        """Safely clear the entries cache so it can be recreated"""
        try:
            del(self.entries)
        except AttributeError:
            # fails in python 2.6.5 with this exception
            pass
        # END exception handling

    @classmethod
    def _read_entry(cls, stream):
        """Return: One entry of the given stream"""
        beginoffset = stream.tell()
        ctime = struct.unpack(">8s", stream.read(8))[0]
        mtime = struct.unpack(">8s", stream.read(8))[0]
        (dev, ino, mode, uid, gid, size, sha, flags) = \
            struct.unpack(">LLLLLL20sH", stream.read(20 + 4 * 6 + 2))
        path_size = flags & 0x0fff
        path = stream.read(path_size)

        real_size = ((stream.tell() - beginoffset + 8) & ~7)
        data = stream.read((beginoffset + real_size) - stream.tell())
        return IndexEntry((mode, binascii.hexlify(sha), flags >> 12, path, ctime, mtime, dev, ino, uid, gid, size))

    @classmethod
    def _read_header(cls, stream):
        """Return tuple(version_long, num_entries) from the given stream"""
        type_id = stream.read(4)
        if type_id != "DIRC":
            raise AssertionError("Invalid index file header: %r" % type_id)
        version, num_entries = struct.unpack(">LL", stream.read(4 * 2))
        assert version in (1, 2)
        return version, num_entries

    def _read_from_stream(self, stream):
        """
        Initialize this instance with index values read from the given stream
        """
        self.version, num_entries = self._read_header(stream)
        count = 0
        self.entries = dict()
        while count < num_entries:
            entry = self._read_entry(stream)
            self.entries[self.get_entries_key(entry)] = entry
            count += 1
        # END for each entry

        # the footer contains extension data and a sha on the content so far
        # Keep the extension footer,and verify we have a sha in the end
        # Extension data format is:
        # 4 bytes ID
        # 4 bytes length of chunk
        # repeated 0 - N times
        self._extension_data = stream.read(~0)
        assert len(self._extension_data) > 19, "Index Footer was not at least a sha on content as it was only %i bytes in size" % len(self._extension_data)

        content_sha = self._extension_data[-20:]

        # truncate the sha in the end as we will dynamically create it anyway
        self._extension_data = self._extension_data[:-20]


    @classmethod
    def _write_cache_entry(cls, stream, entry):
        """
        Write an IndexEntry to a stream
        """
        beginoffset = stream.tell()
        stream.write(entry[4])          # ctime
        stream.write(entry[5])          # mtime
        path = entry[3]
        plen = len(path) & 0x0fff       # path length
        assert plen == len(path), "Path %s too long to fit into index" % entry[3]
        flags = plen | (entry[2] << 12)# stage and path length are 2 byte flags
        stream.write(struct.pack(">LLLLLL20sH", entry[6], entry[7], entry[0],
                                    entry[8], entry[9], entry[10], binascii.unhexlify(entry[1]), flags))
        stream.write(path)
        real_size = ((stream.tell() - beginoffset + 8) & ~7)
        stream.write("\0" * ((beginoffset + real_size) - stream.tell()))

    def write(self, file_path = None, ignore_tree_extension_data=False):
        """
        Write the current state to our file path or to the given one

        ``file_path``
            If None, we will write to our stored file path from which we have
            been initialized. Otherwise we write to the given file path.
            Please note that this will change the file_path of this index to
            the one you gave.

        ``ignore_tree_extension_data``
            If True, the TREE type extension data read in the index will not
            be written to disk. Use this if you have altered the index and
            would like to use git-write-tree afterwards to create a tree
            representing your written changes.
            If this data is present in the written index, git-write-tree
            will instead write the stored/cached tree.
            Alternatively, use IndexFile.write_tree() to handle this case
            automatically

        Returns
            self

        Note
            Index writing based on the dulwich implementation
        """
        write_op = ConcurrentWriteOperation(file_path or self._file_path)
        stream = write_op._begin_writing()

        stream = SHA1Writer(stream)

        # header
        stream.write("DIRC")
        stream.write(struct.pack(">LL", self.version, len(self.entries)))

        # body
        entries_sorted = self.entries.values()
        entries_sorted.sort(key=lambda e: (e[3], e[2]))     # use path/stage as sort key
        for entry in entries_sorted:
            self._write_cache_entry(stream, entry)
        # END for each entry

        stored_ext_data = None
        if ignore_tree_extension_data and self._extension_data and self._extension_data[:4] == 'TREE':
            stored_ext_data = self._extension_data
            self._extension_data = ''
        # END extension data special handling

        # write previously cached extensions data
        stream.write(self._extension_data)

        if stored_ext_data:
            self._extension_data = stored_ext_data
        # END reset previous ext data

        # write the sha over the content
        stream.write_sha()
        write_op._end_writing()

        # make sure we represent what we have written
        if file_path is not None:
            self._file_path = file_path

    @clear_cache
    @default_index
    def merge_tree(self, rhs, base=None):
        """Merge the given rhs treeish into the current index, possibly taking
        a common base treeish into account.

        As opposed to the from_tree_ method, this allows you to use an already
        existing tree as the left side of the merge

        ``rhs``
            treeish reference pointing to the 'other' side of the merge.

        ``base``
            optional treeish reference pointing to the common base of 'rhs' and
            this index which equals lhs

        Returns
            self ( containing the merge and possibly unmerged entries in case of
            conflicts )

        Raise
            GitCommandError in case there is a merge conflict. The error will
            be raised at the first conflicting path. If you want to have proper
            merge resolution to be done by yourself, you have to commit the changed
            index ( or make a valid tree from it ) and retry with a three-way
            index.from_tree call.
        """
        # -i : ignore working tree status
        # --aggressive : handle more merge cases
        # -m : do an actual merge
        args = ["--aggressive", "-i", "-m"]
        if base is not None:
            args.append(base)
        args.append(rhs)

        self.repo.git.read_tree(args)
        return self

    @classmethod
    def from_tree(cls, repo, *treeish, **kwargs):
        """
        Merge the given treeish revisions into a new index which is returned.
        The original index will remain unaltered

        ``repo``
            The repository treeish are located in.

        ``*treeish``
            One, two or three Tree Objects or Commits. The result changes according to the
            amount of trees.
            If 1 Tree is given, it will just be read into a new index
            If 2 Trees are given, they will be merged into a new index using a
             two way merge algorithm. Tree 1 is the 'current' tree, tree 2 is the 'other'
             one. It behaves like a fast-forward.
             If 3 Trees are given, a 3-way merge will be performed with the first tree
             being the common ancestor of tree 2 and tree 3. Tree 2 is the 'current' tree,
             tree 3 is the 'other' one

        ``**kwargs``
            Additional arguments passed to git-read-tree

        Returns
            New IndexFile instance. It will point to a temporary index location which
            does not exist anymore. If you intend to write such a merged Index, supply
            an alternate file_path to its 'write' method.

        Note:
            In the three-way merge case, --aggressive will be specified to automatically
            resolve more cases in a commonly correct manner. Specify trivial=True as kwarg
            to override that.

            As the underlying git-read-tree command takes into account the current index,
            it will be temporarily moved out of the way to assure there are no unsuspected
            interferences.
        """
        if len(treeish) == 0 or len(treeish) > 3:
            raise ValueError("Please specify between 1 and 3 treeish, got %i" % len(treeish))

        arg_list = list()
        # ignore that working tree and index possibly are out of date
        if len(treeish)>1:
            # drop unmerged entries when reading our index and merging
            arg_list.append("--reset")
            # handle non-trivial cases the way a real merge does
            arg_list.append("--aggressive")
        # END merge handling

        # tmp file created in git home directory to be sure renaming
        # works - /tmp/ dirs could be on another device
        tmp_index = tempfile.mktemp('','',repo.git_dir)
        arg_list.append("--index-output=%s" % tmp_index)
        arg_list.extend(treeish)

        # move current index out of the way - otherwise the merge may fail
        # as it considers existing entries. moving it essentially clears the index.
        # Unfortunately there is no 'soft' way to do it.
        # The _TemporaryFileSwap assure the original file get put back
        index_handler = _TemporaryFileSwap(join_path_native(repo.git_dir, 'index'))
        try:
            repo.git.read_tree(*arg_list, **kwargs)
            index = cls(repo, tmp_index)
            index.entries       # force it to read the file as we will delete the temp-file
            del(index_handler)  # release as soon as possible
        finally:
            if os.path.exists(tmp_index):
                os.remove(tmp_index)
        # END index merge handling

        return index

    @classmethod
    def _index_mode_to_tree_index_mode(cls, index_mode):
        """
        Cleanup a index_mode value.
        This will return a index_mode that can be stored in a tree object.

        ``index_mode``
            Index_mode to clean up.
        """
        if stat.S_ISLNK(index_mode):
            return stat.S_IFLNK
        elif stat.S_ISDIR(index_mode):
            return stat.S_IFDIR
        elif stat.S_IFMT(index_mode) == cls.S_IFGITLINK:
            return cls.S_IFGITLINK
        ret = stat.S_IFREG | 0644
        ret |= (index_mode & 0111)
        return ret


    # UTILITIES
    def _iter_expand_paths(self, paths):
        """Expand the directories in list of paths to the corresponding paths accordingly,

        Note: git will add items multiple times even if a glob overlapped
        with manually specified paths or if paths where specified multiple
        times - we respect that and do not prune"""
        def raise_exc(e):
            raise e
        r = self.repo.working_tree_dir
        rs = r + '/'
        for path in paths:
            abs_path = path
            if not os.path.isabs(abs_path):
                abs_path = os.path.join(r, path)
            # END make absolute path

            # resolve globs if possible
            if '?' in path or '*' in path or '[' in path:
                for f in self._iter_expand_paths(glob.glob(abs_path)):
                    yield f.replace(rs, '')
                continue
            # END glob handling
            try:
                for root, dirs, files in os.walk(abs_path, onerror=raise_exc):
                    for rela_file in files:
                        # add relative paths only
                        yield os.path.join(root.replace(rs, ''), rela_file)
                    # END for each file in subdir
                # END for each subdirectory
            except OSError:
                # was a file or something that could not be iterated
                yield path.replace(rs, '')
            # END path exception handling
        # END for each path

    def _write_path_to_stdin(self, proc, filepath, item, append_or_prepend_nl,
                                fmakeexc, fprogress, read_from_stdout=True):
        """Write path to proc.stdin and make sure it processes the item, including progress.

        :return: stdout string
        :param append_or_prepend_nl:
            * if -1, a newline will be sent before the filepath is printed.
            * If 1, a newline will be appended after the filepath was printed.
            * If 0, no additional newline will be sent.
        :param read_from_stdout: if True, proc.stdout will be read after the item
            was sent to stdin. In that case, it will return None
        :note: There is a bug in git-update-index that prevents it from sending
            reports just in time. This is why we have a version that tries to
            read stdout and one which doesn't. In fact, the stdout is not
            important as the piped-in files are processed anyway and just in time
        :note: Newlines are essential here, gits behaviour is somewhat inconsistent
            on this depending on the version, hence we try our best to deal with
            newlines carefully. Usually the last newline will not be sent, instead
            we will close stdin to break the pipe."""

        fprogress(filepath, False, item)
        rval = None
        try:
            if append_or_prepend_nl < 0:
                proc.stdin.write('\n')
            proc.stdin.write("%s" % filepath)
            if append_or_prepend_nl > 0:
                proc.stdin.write('\n')
        except IOError:
            # pipe broke, usually because some error happend
            raise fmakeexc()
        # END write exception handling
        proc.stdin.flush()
        if read_from_stdout:
            rval = proc.stdout.readline().strip()
        fprogress(filepath, True, item)
        return rval

    def iter_blobs(self, predicate = lambda t: True):
        """
        Returns
            Iterator yielding tuples of Blob objects and stages, tuple(stage, Blob)

        ``predicate``
            Function(t) returning True if tuple(stage, Blob) should be yielded by the
            iterator. A default filter, the BlobFilter, allows you to yield blobs
            only if they match a given list of paths.
        """
        for entry in self.entries.itervalues():
            mode = self._index_mode_to_tree_index_mode(entry.mode)
            blob = Blob(self.repo, entry.sha, mode, entry.path)
            blob.size = entry.size
            output = (entry.stage, blob)
            if predicate(output):
                yield output
        # END for each entry

    def unmerged_blobs(self):
        """
        Returns
            Iterator yielding dict(path : list( tuple( stage, Blob, ...))), being
            a dictionary associating a path in the index with a list containing
            sorted stage/blob pairs

        Note:
            Blobs that have been removed in one side simply do not exist in the
            given stage. I.e. a file removed on the 'other' branch whose entries
            are at stage 3 will not have a stage 3 entry.
        """
        is_unmerged_blob = lambda t: t[0] != 0
        path_map = dict()
        for stage, blob in self.iter_blobs(is_unmerged_blob):
            path_map.setdefault(blob.path, list()).append((stage, blob))
        # END for each unmerged blob
        for l in path_map.itervalues():
            l.sort()
        return path_map

    @classmethod
    def get_entries_key(cls, *entry):
        """
        Returns
            Key suitable to be used for the index.entries dictionary

        ``entry``
            One instance of type BaseIndexEntry or the path and the stage
        """
        if len(entry) == 1:
            return (entry[0].path, entry[0].stage)
        else:
            return tuple(entry)


    def resolve_blobs(self, iter_blobs):
        """
        Resolve the blobs given in blob iterator. This will effectively remove the
        index entries of the respective path at all non-null stages and add the given
        blob as new stage null blob.

        For each path there may only be one blob, otherwise a ValueError will be raised
        claiming the path is already at stage 0.

        Raise
            ValueError if one of the blobs already existed at stage 0

        Returns:
            self

        Note
            You will have to write the index manually once you are done, i.e.
            index.resolve_blobs(blobs).write()
        """
        for blob in iter_blobs:
            stage_null_key = (blob.path, 0)
            if stage_null_key in self.entries:
                raise ValueError( "Path %r already exists at stage 0" % blob.path )
            # END assert blob is not stage 0 already

            # delete all possible stages
            for stage in (1, 2, 3):
                try:
                    del( self.entries[(blob.path, stage)] )
                except KeyError:
                    pass
                # END ignore key errors
            # END for each possible stage

            self.entries[stage_null_key] = IndexEntry.from_blob(blob)
        # END for each blob

        return self

    def update(self):
        """
        Reread the contents of our index file, discarding all cached information
        we might have.

        Note:
            This is a possibly dangerious operations as it will discard your changes
            to index.entries

        Returns
            self
        """
        self._delete_entries_cache()
        # allows to lazily reread on demand
        return self

    def write_tree(self, missing_ok=False):
        """
        Writes the Index in self to a corresponding Tree file into the repository
        object database and returns it as corresponding Tree object.

        ``missing_ok``
            If True, missing objects referenced by this index will not result
            in an error.

        Returns
            Tree object representing this index
        """
        index_path = self._index_path()
        tmp_index_mover = _TemporaryFileSwap(index_path)

        self.write(index_path, ignore_tree_extension_data=True)
        tree_sha = self.repo.git.write_tree(missing_ok=missing_ok)

        del(tmp_index_mover)    # as soon as possible

        return Tree(self.repo, tree_sha, 0, '')

    def _process_diff_args(self, args):
        try:
            args.pop(args.index(self))
        except IndexError:
            pass
        # END remove self
        return args


    def _to_relative_path(self, path):
        """
        Return
            Version of path relative to our git directory or raise ValueError
            if it is not within our git direcotory
        """
        if not os.path.isabs(path):
            return path
        relative_path = path.replace(self.repo.working_tree_dir+os.sep, "")
        if relative_path == path:
            raise ValueError("Absolute path %r is not in git repository at %r" % (path,self.repo.working_tree_dir))
        return relative_path

    def _preprocess_add_items(self, items):
        """
        Split the items into two lists of path strings and BaseEntries.
        """
        paths = list()
        entries = list()

        for item in items:
            if isinstance(item, basestring):
                paths.append(self._to_relative_path(item))
            elif isinstance(item, Blob):
                entries.append(BaseIndexEntry.from_blob(item))
            elif isinstance(item, BaseIndexEntry):
                entries.append(item)
            else:
                raise TypeError("Invalid Type: %r" % item)
        # END for each item
        return (paths, entries)


    @clear_cache
    @default_index
    def add(self, items, force=True, fprogress=lambda *args: None, path_rewriter=None):
        """
        Add files from the working tree, specific blobs or BaseIndexEntries
        to the index. The underlying index file will be written immediately, hence
        you should provide as many items as possible to minimize the amounts of writes

        :param items:
            Multiple types of items are supported, types can be mixed within one call.
            Different types imply a different handling. File paths may generally be
            relative or absolute.

            - path string
                strings denote a relative or absolute path into the repository pointing to
                an existing file, i.e. CHANGES, lib/myfile.ext, '/home/gitrepo/lib/myfile.ext'.

                Paths provided like this must exist. When added, they will be written
                into the object database.

                PathStrings may contain globs, such as 'lib/__init__*' or can be directories
                like 'lib', the latter ones will add all the files within the dirctory and
                subdirectories.

                This equals a straight git-add.

                They are added at stage 0

            - Blob object
                Blobs are added as they are assuming a valid mode is set.
                The file they refer to may or may not exist in the file system, but
                must be a path relative to our repository.

                If their sha is null ( 40*0 ), their path must exist in the file system
                relative to the git repository as an object will be created from 
                the data at the path.
                The handling now very much equals the way string paths are processed, except that
                the mode you have set will be kept. This allows you to create symlinks
                by settings the mode respectively and writing the target of the symlink
                directly into the file. This equals a default Linux-Symlink which
                is not dereferenced automatically, except that it can be created on
                filesystems not supporting it as well.

                Please note that globs or directories are not allowed in Blob objects.

                They are added at stage 0

            - BaseIndexEntry or type
                Handling equals the one of Blob objects, but the stage may be
                explicitly set.

        :param force:
            If True, otherwise ignored or excluded files will be
            added anyway.
            As opposed to the git-add command, we enable this flag by default
            as the API user usually wants the item to be added even though
            they might be excluded.

        :param fprogress:
            Function with signature f(path, done=False, item=item) called for each
            path to be added, once once it is about to be added where done==False
            and once after it was added where done=True.
            item is set to the actual item we handle, either a Path or a BaseIndexEntry
            Please note that the processed path is not guaranteed to be present
            in the index already as the index is currently being processed.

        :param path_rewriter:
            Function with signature (string) func(BaseIndexEntry) function returning a path
            for each passed entry which is the path to be actually recorded for the
            object created from entry.path. This allows you to write an index which
            is not identical to the layout of the actual files on your hard-dist.
            If not None and ``items`` contain plain paths, these paths will be
            converted to Entries beforehand and passed to the path_rewriter.
            Please note that entry.path is relative to the git repository.

        :return:
            List(BaseIndexEntries) representing the entries just actually added.

        Raises
            GitCommandError if a supplied Path did not exist. Please note that BaseIndexEntry
            Objects that do not have a null sha will be added even if their paths
            do not exist.
        """
        # sort the entries into strings and Entries, Blobs are converted to entries
        # automatically
        # paths can be git-added, for everything else we use git-update-index
        entries_added = list()
        paths, entries = self._preprocess_add_items(items)

        if paths and path_rewriter:
            for path in paths:
                abspath = os.path.abspath(path)
                gitrelative_path = abspath[len(self.repo.working_tree_dir)+1:]
                blob = Blob(self.repo, Blob.NULL_HEX_SHA, os.stat(abspath).st_mode, gitrelative_path)
                entries.append(BaseIndexEntry.from_blob(blob))
            # END for each path
            del(paths[:])
        # END rewrite paths

        # HANDLE PATHS
        if paths:
            # to get suitable progress information, pipe paths to stdin
            args = ("--add", "--replace", "--verbose", "--stdin")
            proc = self.repo.git.update_index(*args, **{'as_process':True, 'istream':subprocess.PIPE})
            make_exc = lambda : GitCommandError(("git-update-index",)+args, 128, proc.stderr.read())
            added_files = list()

            prepend_newline = 0
            for filepath in self._iter_expand_paths(paths):
                self._write_path_to_stdin(proc, filepath, filepath, prepend_newline, make_exc, fprogress, read_from_stdout=False)
                prepend_newline = -1
                added_files.append(filepath)
            # END for each filepath
            self._flush_stdin_and_wait(proc, ignore_stdout=True)    # ignore stdout

            # force rereading our entries once it is all done
            self._delete_entries_cache()
            entries_added.extend(self.entries[(f,0)] for f in added_files)
        # END path handling

        # HANDLE ENTRIES
        if entries:
            null_mode_entries = [ e for e in entries if e.mode == 0 ]
            if null_mode_entries:
                raise ValueError("At least one Entry has a null-mode - please use index.remove to remove files for clarity")
            # END null mode should be remove

            # HANLDE ENTRY OBJECT CREATION
            # create objects if required, otherwise go with the existing shas
            null_entries_indices = [ i for i,e in enumerate(entries) if e.sha == Object.NULL_HEX_SHA ]
            if null_entries_indices:
                # creating object ids is the time consuming part. Hence we will
                # send progress for these now.
                args = ("-w", "--stdin-paths")
                proc = self.repo.git.hash_object(*args, **{'istream':subprocess.PIPE, 'as_process':True})
                make_exc = lambda : GitCommandError(("git-hash-object",)+args, 128, proc.stderr.read())
                obj_ids = list()
                append_newline = 1
                for ei in null_entries_indices:
                    entry = entries[ei]
                    obj_ids.append(self._write_path_to_stdin(proc, entry.path, entry, append_newline,
                                                                make_exc, fprogress, read_from_stdout=True))
                # END for each entry index
                assert len(obj_ids) == len(null_entries_indices), "git-hash-object did not produce all requested objects: want %i, got %i" % ( len(null_entries_indices), len(obj_ids) )

                # update IndexEntries with new object id
                for i,new_sha in zip(null_entries_indices, obj_ids):
                    e = entries[i]

                    new_entry = BaseIndexEntry((e.mode, new_sha, e.stage, e.path))
                    entries[i] = new_entry
                # END for each index
            # END null_entry handling

            # REWRITE PATHS
            # If we have to rewrite the entries, do so now, after we have generated
            # all object sha's
            if path_rewriter:
                new_entries = list()
                for e in entries:
                    new_entries.append(BaseIndexEntry((e.mode, e.sha, e.stage, path_rewriter(e))))
                # END for each entry
                entries = new_entries
            # END handle path rewriting

            # feed pure entries to stdin
            proc = self.repo.git.update_index(index_info=True, istream=subprocess.PIPE, as_process=True)
            lem1 = len(entries)-1
            for i, entry in enumerate(entries):
                progress_sent = i in null_entries_indices
                if not progress_sent:
                    fprogress(entry.path, False, entry)

                proc.stdin.write(str(entry))

                # the last entry is not \n terminated, as it exepcts to read
                # another entry then and would block. Hence we skip the last one
                if i != lem1:
                    proc.stdin.write('\n')
                    proc.stdin.flush()
                # END skip last newline

                if not progress_sent:
                    fprogress(entry.path, True, entry)
            # END for each enty
            self._flush_stdin_and_wait(proc, ignore_stdout=True)
            entries_added.extend(entries)
        # END if there are base entries

        return entries_added

    def _items_to_rela_paths(self, items):
        """Returns a list of repo-relative paths from the given items which
        may be absolute or relative paths, entries or blobs"""
        paths = list()
        for item in items:
            if isinstance(item, (BaseIndexEntry,Blob)):
                paths.append(self._to_relative_path(item.path))
            elif isinstance(item, basestring):
                paths.append(self._to_relative_path(item))
            else:
                raise TypeError("Invalid item type: %r" % item)
        # END for each item
        return paths

    @clear_cache
    @default_index
    def remove(self, items, working_tree=False, **kwargs):
        """
        Remove the given items from the index and optionally from
        the working tree as well.

        ``items``
            Multiple types of items are supported which may be be freely mixed.

            - path string
                Remove the given path at all stages. If it is a directory, you must
                specify the r=True keyword argument to remove all file entries
                below it. If absolute paths are given, they will be converted
                to a path relative to the git repository directory containing
                the working tree

                The path string may include globs, such as *.c.

            - Blob object
                Only the path portion is used in this case.

            - BaseIndexEntry or compatible type
                The only relevant information here Yis the path. The stage is ignored.

        ``working_tree``
            If True, the entry will also be removed from the working tree, physically
            removing the respective file. This may fail if there are uncommited changes
            in it.

        ``**kwargs``
            Additional keyword arguments to be passed to git-rm, such
            as 'r' to allow recurive removal of

        Returns
            List(path_string, ...) list of repository relative paths that have
            been removed effectively.
            This is interesting to know in case you have provided a directory or
            globs. Paths are relative to the repository.
        """
        args = list()
        if not working_tree:
            args.append("--cached")
        args.append("--")

        # preprocess paths
        paths = self._items_to_rela_paths(items)
        removed_paths = self.repo.git.rm(args, paths, **kwargs).splitlines()

        # process output to gain proper paths
        # rm 'path'
        return [ p[4:-1] for p in removed_paths ]

    @clear_cache
    @default_index
    def move(self, items, skip_errors=False, **kwargs):
        """
        Rename/move the items, whereas the last item is considered the destination of
        the move operation. If the destination is a file, the first item ( of two )
        must be a file as well. If the destination is a directory, it may be preceeded
        by one or more directories or files.

        The working tree will be affected in non-bare repositories.

        ``items``
            Multiple types of items are supported, please see the 'remove' method
            for reference.
        ``skip_errors``
            If True, errors such as ones resulting from missing source files will
            be skpped.
        ``**kwargs``
            Additional arguments you would like to pass to git-mv, such as dry_run
            or force.

        Returns
            List(tuple(source_path_string, destination_path_string), ...)
            A list of pairs, containing the source file moved as well as its
            actual destination. Relative to the repository root.

        Raises
            ValueErorr: If only one item was given
            GitCommandError: If git could not handle your request
        """
        args = list()
        if skip_errors:
            args.append('-k')

        paths = self._items_to_rela_paths(items)
        if len(paths) < 2:
            raise ValueError("Please provide at least one source and one destination of the move operation")

        was_dry_run = kwargs.pop('dry_run', kwargs.pop('n', None))
        kwargs['dry_run'] = True

        # first execute rename in dryrun so the command tells us what it actually does
        # ( for later output )
        out = list()
        mvlines = self.repo.git.mv(args, paths, **kwargs).splitlines()

        # parse result - first 0:n/2 lines are 'checking ', the remaining ones
        # are the 'renaming' ones which we parse
        for ln in xrange(len(mvlines)/2, len(mvlines)):
            tokens = mvlines[ln].split(' to ')
            assert len(tokens) == 2, "Too many tokens in %s" % mvlines[ln]

            # [0] = Renaming x
            # [1] = y
            out.append((tokens[0][9:], tokens[1]))
        # END for each line to parse

        # either prepare for the real run, or output the dry-run result
        if was_dry_run:
            return out
        # END handle dryrun


        # now apply the actual operation
        kwargs.pop('dry_run')
        self.repo.git.mv(args, paths, **kwargs)

        return out

    @default_index
    def commit(self, message, parent_commits=None, head=True):
        """
        Commit the current default index file, creating a commit object.

        For more information on the arguments, see tree.commit.

        ``NOTE``:
            If you have manually altered the .entries member of this instance,
            don't forget to write() your changes to disk beforehand.

        Returns
            Commit object representing the new commit
        """
        tree_sha = self.repo.git.write_tree()
        return Commit.create_from_tree(self.repo, tree_sha, message, parent_commits, head)

    @classmethod
    def _flush_stdin_and_wait(cls, proc, ignore_stdout = False):
        proc.stdin.flush()
        proc.stdin.close()
        stdout = ''
        if not ignore_stdout:
            stdout = proc.stdout.read()
        proc.stdout.close()
        proc.wait()
        return stdout

    @default_index
    def checkout(self, paths=None, force=False, fprogress=lambda *args: None, **kwargs):
        """
        Checkout the given paths or all files from the version known to the index into
        the working tree.

        ``paths``
            If None, all paths in the index will be checked out. Otherwise an iterable
            of relative or absolute paths or a single path pointing to files or directories
            in the index is expected.

        ``force``
            If True, existing files will be overwritten even if they contain local modifications.
            If False, these will trigger a CheckoutError.

        ``fprogress``
            see Index.add_ for signature and explanation.
            The provided progress information will contain None as path and item if no
            explicit paths are given. Otherwise progress information will be send
            prior and after a file has been checked out

        ``**kwargs``
            Additional arguments to be pasesd to git-checkout-index

        Returns
            iterable yielding paths to files which have been checked out and are
            guaranteed to match the version stored in the index

        Raise CheckoutError
            If at least one file failed to be checked out. This is a summary,
            hence it will checkout as many files as it can anyway.
            If one of files or directories do not exist in the index
            ( as opposed to the  original git command who ignores them ).
            Raise GitCommandError if error lines could not be parsed - this truly is
            an exceptional state
        """
        args = ["--index"]
        if force:
            args.append("--force")

        def handle_stderr(proc, iter_checked_out_files):
            stderr = proc.stderr.read()
            if not stderr:
                return
            # line contents:
            # git-checkout-index: this already exists
            failed_files = list()
            failed_reasons = list()
            unknown_lines = list()
            endings = (' already exists', ' is not in the cache', ' does not exist at stage', ' is unmerged')
            for line in stderr.splitlines():
                if not line.startswith("git checkout-index: ") and not line.startswith("git-checkout-index: "):
                    is_a_dir = " is a directory"
                    unlink_issue = "unable to unlink old '"
                    if line.endswith(is_a_dir):
                        failed_files.append(line[:-len(is_a_dir)])
                        failed_reasons.append(is_a_dir)
                    elif line.startswith(unlink_issue):
                        failed_files.append(line[len(unlink_issue):line.rfind("'")])
                        failed_reasons.append(unlink_issue)
                    else:
                        unknown_lines.append(line)
                    continue
                # END special lines parsing

                for e in endings:
                    if line.endswith(e):
                        failed_files.append(line[20:-len(e)])
                        failed_reasons.append(e)
                        break
                    # END if ending matches
                # END for each possible ending
            # END for each line
            if unknown_lines:
                raise GitCommandError(("git-checkout-index", ), 128, stderr)
            if failed_files:
                valid_files = list(set(iter_checked_out_files) - set(failed_files))
                raise CheckoutError("Some files could not be checked out from the index due to local modifications", failed_files, valid_files, failed_reasons)
        # END stderr handler


        if paths is None:
            args.append("--all")
            kwargs['as_process'] = 1
            fprogress(None, False, None)
            proc = self.repo.git.checkout_index(*args, **kwargs)
            proc.wait()
            fprogress(None, True, None)
            rval_iter = ( e.path for e in self.entries.itervalues() )
            handle_stderr(proc, rval_iter)
            return rval_iter
        else:
            if isinstance(paths, basestring):
                paths = [paths]

            args.append("--stdin")
            kwargs['as_process'] = True
            kwargs['istream'] = subprocess.PIPE
            proc = self.repo.git.checkout_index(args, **kwargs)
            make_exc = lambda : GitCommandError(("git-checkout-index",)+tuple(args), 128, proc.stderr.read())
            checked_out_files = list()
            prepend_newline = 0

            for path in paths:
                path = self._to_relative_path(path)
                # if the item is not in the index, it could be a directory
                path_is_directory = False

                try:
                    self.entries[(path, 0)]
                except KeyError:
                    dir = path
                    if not dir.endswith('/'):
                        dir += '/'
                    for entry in self.entries.itervalues():
                        if entry.path.startswith(dir):
                            p = entry.path
                            self._write_path_to_stdin(proc, p, p, prepend_newline,
                                                        make_exc, fprogress, read_from_stdout=False)
                            prepend_newline = -1
                            checked_out_files.append(p)
                            path_is_directory = True
                        # END if entry is in directory
                    # END for each entry
                # END path exception handlnig

                if not path_is_directory:
                    self._write_path_to_stdin(proc, path, path, prepend_newline,
                                                    make_exc, fprogress, read_from_stdout=False)
                    prepend_newline = -1
                    checked_out_files.append(path)
                # END path is a file
            # END for each path
            self._flush_stdin_and_wait(proc, ignore_stdout=True)

            handle_stderr(proc, checked_out_files)
            return checked_out_files
        # END paths handling
        assert "Should not reach this point"

    @clear_cache
    @default_index
    def reset(self, commit='HEAD', working_tree=False, paths=None, head=False, **kwargs):
        """
        Reset the index to reflect the tree at the given commit. This will not
        adjust our HEAD reference as opposed to HEAD.reset by default.

        ``commit``
            Revision, Reference or Commit specifying the commit we should represent.
            If you want to specify a tree only, use IndexFile.from_tree and overwrite
            the default index.

        ``working_tree``
            If True, the files in the working tree will reflect the changed index.
            If False, the working tree will not be touched
            Please note that changes to the working copy will be discarded without
            warning !

        ``head``
            If True, the head will be set to the given commit. This is False by default,
            but if True, this method behaves like HEAD.reset.

        ``**kwargs``
            Additional keyword arguments passed to git-reset

        Returns
            self
        """
        cur_head = self.repo.head
        prev_commit = cur_head.commit

        # reset to get the tree/working copy
        cur_head.reset(commit, index=True, working_tree=working_tree, paths=paths, **kwargs)

        # put the head back, possibly
        if not head:
            cur_head.reset(prev_commit, index=False, working_tree=False)
        # END reset head

        return self

    @default_index
    def diff(self, other=diff.Diffable.Index, paths=None, create_patch=False, **kwargs):
        """
        Diff this index against the working copy or a Tree or Commit object

        For a documentation of the parameters and return values, see
        Diffable.diff

        Note
            Will only work with indices that represent the default git index as
            they have not been initialized with a stream.
        """
        # index against index is always empty
        if other is self.Index:
            return diff.DiffIndex()

        # index against anything but None is a reverse diff with the respective
        # item. Handle existing -R flags properly. Transform strings to the object
        # so that we can call diff on it
        if isinstance(other, basestring):
            other = Object.new(self.repo, other)
        # END object conversion

        if isinstance(other, Object):
            # invert the existing R flag
            cur_val = kwargs.get('R', False)
            kwargs['R'] = not cur_val
            return other.diff(self.Index, paths, create_patch, **kwargs)
        # END diff against other item handlin

        # if other is not None here, something is wrong
        if other is not None:
            raise ValueError( "other must be None, Diffable.Index, a Tree or Commit, was %r" % other )

        # diff against working copy - can be handled by superclass natively
        return super(IndexFile, self).diff(other, paths, create_patch, **kwargs)

