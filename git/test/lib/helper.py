# helper.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php
from __future__ import print_function

import os
from unittest import TestCase
import time
import tempfile
import io
import logging

from functools import wraps

from git.util import rmtree
from git.compat import string_types, is_win
import textwrap

osp = os.path.dirname

GIT_REPO = os.environ.get("GIT_PYTHON_TEST_GIT_REPO_BASE", osp(osp(osp(osp(__file__)))))
GIT_DAEMON_PORT = os.environ.get("GIT_PYTHON_TEST_GIT_DAEMON_PORT", "9418")

__all__ = (
    'fixture_path', 'fixture', 'absolute_project_path', 'StringProcessAdapter',
    'with_rw_directory', 'with_rw_repo', 'with_rw_and_rw_remote_repo', 'TestBase', 'TestCase',
    'GIT_REPO', 'GIT_DAEMON_PORT'
)

log = logging.getLogger('git.util')

#: We need an easy way to see if Appveyor TCs start failing,
#: so the errors marked with this var are considered "acknowledged" ones, awaiting remedy,
#: till then, we wish to hide them.
HIDE_WINDOWS_KNOWN_ERRORS = is_win and os.environ.get('HIDE_WINDOWS_KNOWN_ERRORS', True)

#{ Routines


def fixture_path(name):
    test_dir = osp(osp(__file__))
    return os.path.join(test_dir, "fixtures", name)


def fixture(name):
    with open(fixture_path(name), 'rb') as fd:
        return fd.read()


def absolute_project_path():
    return os.path.abspath(os.path.join(osp(__file__), "..", ".."))

#} END routines

#{ Adapters


class StringProcessAdapter(object):

    """Allows to use strings as Process object as returned by SubProcess.Popen.
    Its tailored to work with the test system only"""

    def __init__(self, input_string):
        self.stdout = io.BytesIO(input_string)
        self.stderr = io.BytesIO()

    def wait(self):
        return 0

    poll = wait

#} END adapters

#{ Decorators


def _mktemp(*args):
    """Wrapper around default tempfile.mktemp to fix an osx issue
    :note: the OSX special case was removed as it was unclear why that was needed in the first place. It seems
    to be just fine without it. However, if we leave this special case, and if TMPDIR is set to something custom,
    prefixing /private/ will lead to incorrect paths on OSX."""
    tdir = tempfile.mktemp(*args)
    # See :note: above to learn why this is comented out.
    # if is_darwin:
    #     tdir = '/private' + tdir
    return tdir


def with_rw_directory(func):
    """Create a temporary directory which can be written to, remove it if the
    test succeeds, but leave it otherwise to aid additional debugging"""

    @wraps(func)
    def wrapper(self):
        path = tempfile.mktemp(prefix=func.__name__)
        os.mkdir(path)
        keep = False
        try:
            try:
                return func(self, path)
            except Exception:
                log.info("Test %s.%s failed, output is at %r\n",
                         type(self).__name__, func.__name__, path)
                keep = True
                raise
        finally:
            # Need to collect here to be sure all handles have been closed. It appears
            # a windows-only issue. In fact things should be deleted, as well as
            # memory maps closed, once objects go out of scope. For some reason
            # though this is not the case here unless we collect explicitly.
            import gc
            gc.collect()
            if not keep:
                rmtree(path)

    return wrapper


def with_rw_repo(working_tree_ref, bare=False):
    """
    Same as with_bare_repo, but clones the rorepo as non-bare repository, checking
    out the working tree at the given working_tree_ref.

    This repository type is more costly due to the working copy checkout.

    To make working with relative paths easier, the cwd will be set to the working
    dir of the repository.
    """
    assert isinstance(working_tree_ref, string_types), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):
        @wraps(func)
        def repo_creator(self):
            prefix = 'non_'
            if bare:
                prefix = ''
            # END handle prefix
            repo_dir = _mktemp("%sbare_%s" % (prefix, func.__name__))
            rw_repo = self.rorepo.clone(repo_dir, shared=True, bare=bare, n=True)

            rw_repo.head.commit = rw_repo.commit(working_tree_ref)
            if not bare:
                rw_repo.head.reference.checkout()
            # END handle checkout

            prev_cwd = os.getcwd()
            os.chdir(rw_repo.working_dir)
            try:
                try:
                    return func(self, rw_repo)
                except:
                    log.info("Keeping repo after failure: %s", repo_dir)
                    repo_dir = None
                    raise
            finally:
                os.chdir(prev_cwd)
                rw_repo.git.clear_cache()
                rw_repo = None
                import gc
                gc.collect()
                if repo_dir is not None:
                    rmtree(repo_dir)
                # END rm test repo if possible
            # END cleanup
        # END rw repo creator
        return repo_creator
    # END argument passer
    return argument_passer


def launch_git_daemon(temp_dir, ip, port):
    from git import Git
    if is_win:
        ## On MINGW-git, daemon exists in .\Git\mingw64\libexec\git-core\,
        #  but if invoked as 'git daemon', it detaches from parent `git` cmd,
        #  and then CANNOT DIE!
        #  So, invoke it as a single command.
        ## Cygwin-git has no daemon.
        #
        daemon_cmd = ['git-daemon', temp_dir,
                      '--enable=receive-pack',
                      '--listen=%s' % ip,
                      '--port=%s' % port]
        gd = Git().execute(daemon_cmd, as_process=True)
    else:
        gd = Git().daemon(temp_dir,
                          enable='receive-pack',
                          listen=ip,
                          port=port,
                          as_process=True)
    return gd


def with_rw_and_rw_remote_repo(working_tree_ref):
    """
    Same as with_rw_repo, but also provides a writable remote repository from which the
    rw_repo has been forked as well as a handle for a git-daemon that may be started to
    run the remote_repo.
    The remote repository was cloned as bare repository from the rorepo, wheras
    the rw repo has a working tree and was cloned from the remote repository.

    remote_repo has two remotes: origin and daemon_origin. One uses a local url,
    the other uses a server url. The daemon setup must be done on system level
    and should be an inetd service that serves tempdir.gettempdir() and all
    directories in it.

    The following scetch demonstrates this::
     rorepo ---<bare clone>---> rw_remote_repo ---<clone>---> rw_repo

    The test case needs to support the following signature::
        def case(self, rw_repo, rw_remote_repo)

    This setup allows you to test push and pull scenarios and hooks nicely.

    See working dir info in with_rw_repo
    :note: We attempt to launch our own invocation of git-daemon, which will be shutdown at the end of the test.
    """
    from git import Remote, GitCommandError
    assert isinstance(working_tree_ref, string_types), "Decorator requires ref name for working tree checkout"

    def argument_passer(func):

        @wraps(func)
        def remote_repo_creator(self):
            remote_repo_dir = _mktemp("remote_repo_%s" % func.__name__)
            repo_dir = _mktemp("remote_clone_non_bare_repo")

            rw_remote_repo = self.rorepo.clone(remote_repo_dir, shared=True, bare=True)
            # recursive alternates info ?
            rw_repo = rw_remote_repo.clone(repo_dir, shared=True, bare=False, n=True)
            rw_repo.head.commit = working_tree_ref
            rw_repo.head.reference.checkout()

            # prepare for git-daemon
            rw_remote_repo.daemon_export = True

            # this thing is just annoying !
            with rw_remote_repo.config_writer() as crw:
                section = "daemon"
                try:
                    crw.add_section(section)
                except Exception:
                    pass
                crw.set(section, "receivepack", True)

            # initialize the remote - first do it as local remote and pull, then
            # we change the url to point to the daemon. The daemon should be started
            # by the user, not by us
            d_remote = Remote.create(rw_repo, "daemon_origin", remote_repo_dir)
            d_remote.fetch()
            remote_repo_url = "git://localhost:%s%s" % (GIT_DAEMON_PORT, remote_repo_dir)

            with d_remote.config_writer as cw:
                cw.set('url', remote_repo_url)

            temp_dir = osp(_mktemp())
            gd = launch_git_daemon(temp_dir, '127.0.0.1', GIT_DAEMON_PORT)
            try:
                # yes, I know ... fortunately, this is always going to work if sleep time is just large enough
                time.sleep(0.5)
            # end

                # try to list remotes to diagnoes whether the server is up
                try:
                    rw_repo.git.ls_remote(d_remote)
                except GitCommandError as e:
                    # We assume in good faith that we didn't start the daemon - but make sure we kill it anyway
                    # Of course we expect it to work here already, but maybe there are timing constraints
                    # on some platforms ?
                    try:
                        gd.proc.terminate()
                    except Exception as ex:
                        log.debug("Ignoring %r while terminating proc after %r.", ex, e)
                    log.warning('git(%s) ls-remote failed due to:%s',
                                rw_repo.git_dir, e)
                    if is_win:
                        msg = textwrap.dedent("""
                        MINGW yet has problems with paths, and `git-daemon.exe` must be in PATH
                        (look into .\Git\mingw64\libexec\git-core\);
                        CYGWIN has no daemon, but if one exists, it gets along fine (has also paths problems)
                        Anyhow, alternatively try starting `git-daemon` manually:""")
                    else:
                        msg = "Please try starting `git-daemon` manually:"

                    msg += textwrap.dedent("""
                        git daemon --enable=receive-pack '%s'
                    You can also run the daemon on a different port by passing --port=<port>"
                    and setting the environment variable GIT_PYTHON_TEST_GIT_DAEMON_PORT to <port>
                    """ % temp_dir)
                    from nose import SkipTest
                    raise SkipTest(msg) if is_win else AssertionError(msg)
                    # END make assertion
                # END catch ls remote error

                # adjust working dir
                prev_cwd = os.getcwd()
                os.chdir(rw_repo.working_dir)

                try:
                    return func(self, rw_repo, rw_remote_repo)
                except:
                    log.info("Keeping repos after failure: repo_dir = %s, remote_repo_dir = %s",
                             repo_dir, remote_repo_dir)
                    repo_dir = remote_repo_dir = None
                    raise
                finally:
                    os.chdir(prev_cwd)

            finally:
                try:
                    gd.proc.kill()
                except:
                    ## Either it has died (and we're here), or it won't die, again here...
                    pass

                rw_repo.git.clear_cache()
                rw_remote_repo.git.clear_cache()
                rw_repo = rw_remote_repo = None
                import gc
                gc.collect()
                if repo_dir:
                    rmtree(repo_dir)
                if remote_repo_dir:
                    rmtree(remote_repo_dir)

                if gd is not None:
                    gd.proc.wait()
            # END cleanup
        # END bare repo creator
        return remote_repo_creator
        # END remote repo creator
    # END argument parser

    return argument_passer

#} END decorators


class TestBase(TestCase):

    """
    Base Class providing default functionality to all tests such as:

    - Utility functions provided by the TestCase base of the unittest method such as::
        self.fail("todo")
        self.failUnlessRaises(...)

    - Class level repository which is considered read-only as it is shared among
      all test cases in your type.
      Access it using::
       self.rorepo  # 'ro' stands for read-only

      The rorepo is in fact your current project's git repo. If you refer to specific
      shas for your objects, be sure you choose some that are part of the immutable portion
      of the project history ( to assure tests don't fail for others ).
    """

    def _small_repo_url(self):
        """:return" a path to a small, clonable repository"""
        return os.path.join(self.rorepo.working_tree_dir, 'git/ext/gitdb/gitdb/ext/smmap')

    @classmethod
    def setUpClass(cls):
        """
        Dynamically add a read-only repository to our actual type. This way
        each test type has its own repository
        """
        from git import Repo
        import gc
        gc.collect()
        cls.rorepo = Repo(GIT_REPO)

    @classmethod
    def tearDownClass(cls):
        cls.rorepo.git.clear_cache()
        cls.rorepo.git = None

    def _make_file(self, rela_path, data, repo=None):
        """
        Create a file at the given path relative to our repository, filled
        with the given data. Returns absolute path to created file.
        """
        repo = repo or self.rorepo
        abs_path = os.path.join(repo.working_tree_dir, rela_path)
        with open(abs_path, "w") as fp:
            fp.write(data)
        return abs_path
