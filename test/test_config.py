# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under the
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/

import glob
import configparser as cp
import io
import os
import os.path as osp
import sys
from unittest import mock

import pytest

from git import Git, GitConfigParser
from git.config import _escape_config_value, _escape_section_subsection
from git.util import rmfile

from test.lib import SkipTest, TestCase, fixture_path, with_rw_directory

_tc_lock_fpaths = osp.join(osp.dirname(__file__), "fixtures/*.lock")


def _rm_lock_files():
    for lfp in glob.glob(_tc_lock_fpaths):
        rmfile(lfp)


class TestBase(TestCase):
    def setUp(self):
        _rm_lock_files()

    def tearDown(self):
        for lfp in glob.glob(_tc_lock_fpaths):
            if osp.isfile(lfp):
                raise AssertionError("Previous TC left hanging git-lock file: {}".format(lfp))

    def _to_memcache(self, file_path):
        with open(file_path, "rb") as fp:
            sio = io.BytesIO(fp.read())
        sio.name = file_path
        return sio

    def test_read_write(self):
        # The writer must create the exact same file as the one read before.
        for filename in ("git_config", "git_config_global"):
            file_obj = self._to_memcache(fixture_path(filename))
            with GitConfigParser(file_obj, read_only=False) as w_config:
                w_config.read()  # Enforce reading.
                assert w_config._sections
                w_config.write()  # Enforce writing.

                # We stripped lines when reading, so the results differ.
                assert file_obj.getvalue()
                self.assertEqual(
                    file_obj.getvalue(),
                    self._to_memcache(fixture_path(filename)).getvalue(),
                )

                # Creating an additional config writer must fail due to exclusive
                # access.
                with self.assertRaises(IOError):
                    GitConfigParser(file_obj, read_only=False)

                # Should still have a lock and be able to make changes.
                assert w_config._lock._has_lock()

                # Changes should be written right away.
                sname = "my-section"
                oname = "mykey"
                val = "myvalue"
                w_config.add_section(sname)
                assert w_config.has_section(sname)
                w_config.set(sname, oname, val)
                assert w_config.has_option(sname, oname)
                assert w_config.get(sname, oname) == val

                sname_new = "new-section"
                oname_new = "new-key"
                ival = 10
                w_config.set_value(sname_new, oname_new, ival)
                assert w_config.get_value(sname_new, oname_new) == ival

                file_obj.seek(0)
                r_config = GitConfigParser(file_obj, read_only=True)
                assert r_config.has_section(sname)
                assert r_config.has_option(sname, oname)
                assert r_config.get(sname, oname) == val
        # END for each filename

    def test_includes_order(self):
        with GitConfigParser(list(map(fixture_path, ("git_config", "git_config_global")))) as r_config:
            r_config.read()  # Enforce reading.
            # Simple inclusions, again checking them taking precedence.
            assert r_config.get_value("sec", "var0") == "value0_included"
            # This one should take the git_config_global value since included values
            # must be considered as soon as they get them.
            assert r_config.get_value("diff", "tool") == "meld"
            try:
                # FIXME: Split this assertion out somehow and mark it xfail (or fix it).
                assert r_config.get_value("sec", "var1") == "value1_main"
            except AssertionError as e:
                raise SkipTest("Known failure -- included values are not in effect right away") from e

    @with_rw_directory
    def test_lock_reentry(self, rw_dir):
        fpl = osp.join(rw_dir, "l")
        gcp = GitConfigParser(fpl, read_only=False)
        with gcp as cw:
            cw.set_value("include", "some-value", "a")
        # Entering again locks the file again...
        with gcp as cw:
            cw.set_value("include", "some-other-value", "b")
            # ...so creating an additional config writer must fail due to exclusive
            # access.
            with self.assertRaises(IOError):
                GitConfigParser(fpl, read_only=False)
        # but work when the lock is removed
        with GitConfigParser(fpl, read_only=False):
            assert osp.exists(fpl)
            # Reentering with an existing lock must fail due to exclusive access.
            with self.assertRaises(IOError):
                gcp.__enter__()

    def test_multi_line_config(self):
        file_obj = self._to_memcache(fixture_path("git_config_with_comments"))
        with GitConfigParser(file_obj, read_only=False) as config:
            ev = "ruby -e '\n"
            ev += "		system %(git), %(merge-file), %(--marker-size=%L), %(%A), %(%O), %(%B)\n"
            ev += "		b = File.read(%(%A))\n"
            ev += "		b.sub!(/^<+ .*\\nActiveRecord::Schema\\.define.:version => (\\d+). do\\n=+\\nActiveRecord::Schema\\."  # noqa: E501
            ev += "define.:version => (\\d+). do\\n>+ .*/) do\n"
            ev += "		  %(ActiveRecord::Schema.define(:version => #{[$1, $2].max}) do)\n"
            ev += "		end\n"
            ev += "		File.open(%(%A), %(w)) {|f| f.write(b)}\n"
            ev += "		exit 1 if b.include?(%(<)*%L)'"
            self.assertEqual(config.get('merge "railsschema"', "driver"), ev)
            self.assertEqual(
                config.get("alias", "lg"),
                "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'"
                " --abbrev-commit --date=relative",
            )
            self.assertEqual(len(config.sections()), 23)

    def test_config_rejects_colon_delimiter_and_unterminated_quote(self):
        config_content = b'[section-header]\nkey:"value\n"'
        config_file = io.BytesIO(config_content)
        config_file.name = "multiline_value.config"

        git_config = GitConfigParser(config_file)
        with pytest.raises(cp.ParsingError):
            git_config.read()

    def test_git_parser_handles_stream_syntax_comments_and_continuations(self):
        config_file = io.BytesIO(
            b"\xef\xbb\xbf; comment\r\n[Core] [other]\r\nenabled\r\npath = one\\\r\n two # trailing comment\r\n"
        )
        config_file.name = "git-syntax.config"

        git_config = GitConfigParser(config_file)
        self.assertEqual(git_config.sections(), ["Core", "other"])
        self.assertTrue(git_config.has_section("CORE"))
        self.assertIs(git_config.get_value("other", "enabled"), True)
        self.assertEqual(git_config.get_value("other", "path"), "one two")

    @with_rw_directory
    def test_section_and_option_case_match_git(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        with open(config_path, "wb") as config_file:
            config_file.write(b'[CoRe]\n\tMixedOption = "one"\n[Remote "Origin"]\n\tFetchURL = "example"\n')

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.set_value("CORE", "MIXEDOPTION", "two")
            git_config.set_value("core", "NewOption", "new")

            self.assertEqual(git_config.sections(), ["CoRe", 'Remote "Origin"'])
            self.assertEqual(git_config.get_value("cOrE", "mixedOPTION"), "two")
            self.assertEqual(git_config.get_values("CORE", "MixedOption"), ["two"])
            self.assertEqual(git_config.options("CORE"), ["MixedOption", "NewOption"])
            self.assertEqual(git_config.items("CORE"), [("MixedOption", "two"), ("NewOption", "new")])
            self.assertEqual(git_config.items_all("CORE"), [("MixedOption", ["two"]), ("NewOption", ["new"])])
            core = git_config["CORE"]
            self.assertEqual(core.name, "CoRe")
            self.assertEqual(list(core), ["MixedOption", "NewOption"])
            self.assertEqual(list(core.items()), [("MixedOption", "two"), ("NewOption", "new")])
            self.assertEqual(core["MixedOption"], "two")
            self.assertEqual(list(git_config), ["CoRe", 'Remote "Origin"'])
            self.assertTrue(git_config.has_option("CORE", "MixedOption"))
            self.assertTrue(git_config.has_section('REMOTE "Origin"'))
            self.assertFalse(git_config.has_section('remote "origin"'))

        with open(config_path, "rb") as config_file:
            self.assertEqual(
                config_file.read(),
                b'[CoRe]\n\tMixedOption = "two"\n\tNewOption = "new"\n[Remote "Origin"]\n\tFetchURL = "example"\n',
            )

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.rename_section('REMOTE "Origin"', 'Branch "Origin"')
            self.assertEqual(git_config.get_value('BRANCH "Origin"', "fetchurl"), "example")
            self.assertEqual(git_config.sections(), ["CoRe", 'Branch "Origin"'])
            self.assertEqual(git_config.options('branch "Origin"'), ["FetchURL"])
            self.assertEqual(git_config['branch "Origin"'].name, 'Branch "Origin"')

        with open(config_path, "rb") as config_file:
            self.assertEqual(
                config_file.read(),
                b'[CoRe]\n\tMixedOption = "two"\n\tNewOption = "new"\n[Branch "Origin"]\n\tFetchURL = "example"\n',
            )

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.get_value("CORE", "MIXEDOPTION"), "two")
            self.assertEqual(git_config.get_value('branch "Origin"', "FETCHURL"), "example")

    def test_git_parser_rejects_syntax_rejected_by_git(self):
        invalid_configs = (
            b"[  gui]\nkey = value\n",
            b"[core]\nbad_key = value\n",
            b"[core]\nkey: value\n",
            b'[core]\nkey = "unterminated\n',
            b'[core]\nkey = "bad\\q"\n',
            b'[core]\nkey = "bad\x00value"\n',
        )
        for config_content in invalid_configs:
            with self.subTest(config_content=config_content):
                config_file = io.BytesIO(config_content)
                config_file.name = "invalid-git-syntax.config"

                with pytest.raises(cp.ParsingError):
                    GitConfigParser(config_file).read()

    @with_rw_directory
    def test_git_parser_and_canonical_writer_round_trip(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        section = 'submodule "docs]archive"'
        value = ' leading #; "quoted" \\ tail\nsecond\tcolumn\b'
        with open(config_path, "wb") as config_file:
            config_file.write(
                b'[submodule "docs]archive"]\npayload = " leading #; \\"quoted\\" \\\\ tail\\nsecond\\tcolumn\\b"\n'
            )

        with GitConfigParser(config_path, read_only=False) as git_config:
            self.assertEqual(git_config.get_value(section, "payload"), value)
            git_config.set_value(section, "other", "x#;y")

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.get_value(section, "payload"), value)
            self.assertEqual(git_config.get_value(section, "other"), "x#;y")

        with open(config_path, "rb") as config_file:
            self.assertEqual(
                config_file.read(),
                b'[submodule "docs]archive"]\n'
                b'\tpayload = " leading #; \\"quoted\\" \\\\ tail\\nsecond\\tcolumn\\b"\n'
                b'\tother = "x#;y"\n',
            )

        self.assertEqual(Git().config("--file", config_path, "--get", "submodule.docs]archive.payload"), value)

    @with_rw_directory
    def test_writer_rejects_names_outside_git_grammar(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.add_section("core")
            for option in ("bad_option", "-bad", "bad.option"):
                with self.subTest(option=option), pytest.raises(ValueError, match="option names"):
                    git_config.set_value("core", option, "value")

            for section in (" gui", "user trailing", "user] [other"):
                with self.subTest(section=section), pytest.raises(ValueError, match="section name"):
                    git_config.add_section(section)

    @with_rw_directory
    def test_writer_escapes_quoted_subsection_names(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        section = 'submodule "docs\\"archive\\\\part]"'
        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.set_value(section, "path", "docs")

        with open(config_path, "rb") as config_file:
            self.assertEqual(config_file.read(), b'[submodule "docs\\"archive\\\\part]"]\n\tpath = "docs"\n')

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.sections(), [section])
            self.assertEqual(git_config.get_value(section, "path"), "docs")

        self.assertEqual(Git().config("--file", config_path, "--get", 'submodule.docs"archive\\part].path'), "docs")

    @with_rw_directory
    def test_set_value_escapes_config_injection(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        payload = "foo\n[core]\nhooksPath=/tmp/hooks"

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.set_value("user", "name", payload)

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.get_value("user", "name"), payload)
            self.assertFalse(git_config.has_section("core"))

    @with_rw_directory
    def test_set_value_rejects_unsafe_section_and_option_names(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        bad_keys = ("user]\n[core", "user]\r[core", "user]\x00[core")

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.add_section("user")
            for bad_key in bad_keys:
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.add_section(bad_key)
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.set(bad_key, "hooksPath", "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.set("user", bad_key, "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.set_value(bad_key, "hooksPath", "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.set_value("user", bad_key, "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.add_value(bad_key, "hooksPath", "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.add_value("user", bad_key, "/tmp/hooks")
                with pytest.raises(ValueError, match="CR, LF, or NUL"):
                    git_config.rename_section("user", bad_key)

            git_config.set_value("user", "name", "safe")

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.get_value("user", "name"), "safe")
            self.assertFalse(git_config.has_section("core"))

    @with_rw_directory
    def test_writer_rejects_unquoted_section_terminators(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        bad_sections = ("user] [other", 'submodule "docs"] [other')
        safe_section = 'submodule "docs]archive"'

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.add_section("user")
            for bad_section in bad_sections:
                with pytest.raises(ValueError, match="section name"):
                    git_config.add_section(bad_section)
                with pytest.raises(ValueError, match="section name"):
                    git_config.set(bad_section, "name", "value")
                with pytest.raises(ValueError, match="section name"):
                    git_config.set_value(bad_section, "name", "value")
                with pytest.raises(ValueError, match="section name"):
                    git_config.add_value(bad_section, "name", "value")
                with pytest.raises(ValueError, match="section name"):
                    git_config.rename_section("user", bad_section)

            git_config.set_value("user", "name", "safe")
            git_config.set_value(safe_section, "name", "safe")
            self.assertEqual(git_config.get_value(safe_section, "name"), "safe")

        # A closing bracket inside a quoted subsection name is data, not a section terminator.
        with open(config_path, "rb") as config_file:
            self.assertIn(
                b'[submodule "docs]archive"]\n',
                config_file.read(),
                "a closing bracket within a quoted subsection name should be preserved",
            )

        # Reparse the file to verify that rejected names did not inject an [other] section.
        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(
                git_config.get_value("user", "name"),
                "safe",
                "rejected section names corrupted the existing section",
            )
            self.assertFalse(git_config.has_section("other"), "an unsafe section name injected an [other] section")

    @with_rw_directory
    def test_set_and_add_value_match_git_control_character_handling(self, rw_dir):
        config_path = osp.join(rw_dir, "config")

        with GitConfigParser(config_path, read_only=False) as git_config:
            git_config.add_section("user")
            git_config.set("user", "carriage-return", "foo\rbar")
            git_config.set_value("user", "line-feed", "foo\nbar")
            git_config.add_value("user", "bytes-line-feed", b"foo\nbar")

            for setter in (git_config.set, git_config.set_value, git_config.add_value):
                with pytest.raises(ValueError, match="must not contain NUL"):
                    setter("user", "name", "foo\x00bar")

        with GitConfigParser(config_path, read_only=True) as git_config:
            self.assertEqual(git_config.get_value("user", "carriage-return"), "foo\rbar")
            self.assertEqual(git_config.get_value("user", "line-feed"), "foo\nbar")
            self.assertEqual(git_config.get_value("user", "bytes-line-feed"), "foo\nbar")

        self.assertEqual(Git().config("--file", config_path, "--get", "user.carriage-return"), "foo\rbar")
        self.assertEqual(Git().config("--file", config_path, "--get", "user.line-feed"), "foo\nbar")

    def test_base(self):
        path_repo = fixture_path("git_config")
        path_global = fixture_path("git_config_global")
        r_config = GitConfigParser([path_repo, path_global], read_only=True)
        assert r_config.read_only
        num_sections = 0
        num_options = 0

        # Test reader methods.
        assert r_config._is_initialized is False
        for section in r_config.sections():
            num_sections += 1
            for option in r_config.options(section):
                num_options += 1
                val = r_config.get(section, option)
                val_typed = r_config.get_value(section, option)
                assert isinstance(val_typed, (bool, int, float, str))
                assert val
                assert "\n" not in option
                assert "\n" not in val

                # Writing must fail.
                with self.assertRaises(IOError):
                    r_config.set(section, option, None)
                with self.assertRaises(IOError):
                    r_config.remove_option(section, option)
            # END for each option
            with self.assertRaises(IOError):
                r_config.remove_section(section)
        # END for each section
        assert num_sections and num_options
        assert r_config._is_initialized is True

        # Get value which doesn't exist, with default.
        default = "my default value"
        assert r_config.get_value("doesnt", "exist", default) == default

        # It raises if there is no default though.
        with self.assertRaises(cp.NoSectionError):
            r_config.get_value("doesnt", "exist")

    @with_rw_directory
    def test_config_include(self, rw_dir):
        def write_test_value(cw, value):
            cw.set_value(value, "value", value)

        def check_test_value(cr, value):
            assert cr.get_value(value, "value") == value

        # PREPARE CONFIG FILE A
        fpa = osp.join(rw_dir, "a")
        with GitConfigParser(fpa, read_only=False) as cw:
            write_test_value(cw, "a")

            fpb = osp.join(rw_dir, "b")
            fpc = osp.join(rw_dir, "c")
            cw.set_value("include", "relative-path-b", "b")
            cw.set_value("include", "doesntexist", "foobar")
            cw.set_value("include", "relative-cycle-a-a", "a")
            cw.set_value("include", "absolute-cycle-a-a", fpa)
        assert osp.exists(fpa)

        # PREPARE CONFIG FILE B
        with GitConfigParser(fpb, read_only=False) as cw:
            write_test_value(cw, "b")
            cw.set_value("include", "relative-cycle-b-a", "a")
            cw.set_value("include", "absolute-cycle-b-a", fpa)
            cw.set_value("include", "relative-path-c", "c")
            cw.set_value("include", "absolute-path-c", fpc)

        # PREPARE CONFIG FILE C
        with GitConfigParser(fpc, read_only=False) as cw:
            write_test_value(cw, "c")

        with GitConfigParser(fpa, read_only=True) as cr:
            for tv in ("a", "b", "c"):
                check_test_value(cr, tv)
            # END for each test to verify
            assert len(cr.items("include")) == 8, "Expected all include sections to be merged"

        # Test writable config writers - assure write-back doesn't involve includes.
        with GitConfigParser(fpa, read_only=False, merge_includes=True) as cw:
            tv = "x"
            write_test_value(cw, tv)

        with GitConfigParser(fpa, read_only=True) as cr:
            with self.assertRaises(cp.NoSectionError):
                check_test_value(cr, tv)

        # But can make it skip includes altogether, and thus allow write-backs.
        with GitConfigParser(fpa, read_only=False, merge_includes=False) as cw:
            write_test_value(cw, tv)

        with GitConfigParser(fpa, read_only=True) as cr:
            check_test_value(cr, tv)

    @with_rw_directory
    def test_config_relative_path_include(self, rw_dir):
        included_path = osp.join(rw_dir, "included")
        with GitConfigParser(included_path, read_only=False) as cw:
            cw.set_value("included", "value", "included")

        config_path = osp.join(rw_dir, "config")
        with GitConfigParser(config_path, read_only=False) as cw:
            cw.set_value("include", "path", "included")

        if osp.splitdrive(config_path)[0] != osp.splitdrive(os.getcwd())[0]:
            pytest.skip("The temporary directory and checkout are on different drives")

        relative_config_path = osp.relpath(config_path)
        with GitConfigParser(relative_config_path, read_only=True) as cr:
            assert cr.get_value("included", "value") == "included"

    @with_rw_directory
    def test_multiple_include_paths_with_same_key(self, rw_dir):
        """Test that multiple 'path' entries under [include] are all respected.

        Regression test for https://github.com/gitpython-developers/GitPython/issues/2099.
        Git config allows multiple ``path`` values under ``[include]``, e.g.::

            [include]
                path = file1
                path = file2

        Previously only one of these was included because the old INI-backed storage
        exposed only the last value for each key.
        """
        # Create two config files to be included.
        fp_inc1 = osp.join(rw_dir, "inc1.cfg")
        fp_inc2 = osp.join(rw_dir, "inc2.cfg")
        fp_main = osp.join(rw_dir, "main.cfg")

        with GitConfigParser(fp_inc1, read_only=False) as cw:
            cw.set_value("user", "name", "from-inc1")

        with GitConfigParser(fp_inc2, read_only=False) as cw:
            cw.set_value("core", "bar", "from-inc2")

        # Write a config with two path entries under a single [include] section.
        # We write it manually because set_value would overwrite the key.
        with open(fp_main, "w") as f:
            f.write("[include]\n")
            f.write(f"\tpath = {_escape_config_value(fp_inc1)}\n")
            f.write(f"\tpath = {_escape_config_value(fp_inc2)}\n")

        with GitConfigParser(fp_main, read_only=True) as cr:
            # Both included files should be loaded.
            assert cr.get_value("user", "name") == "from-inc1"
            assert cr.get_value("core", "bar") == "from-inc2"

    @pytest.mark.xfail(
        sys.platform == "win32",
        reason='Second config._has_includes() assertion fails (for "config is included if path is matching git_dir")',
        raises=AssertionError,
    )
    @with_rw_directory
    def test_conditional_includes_from_git_dir(self, rw_dir):
        # Initiate repository path.
        git_dir = osp.join(rw_dir, "target1", "repo1")
        os.makedirs(git_dir)

        # Initiate mocked repository.
        repo = mock.Mock(git_dir=git_dir)

        # Initiate config files.
        path1 = osp.join(rw_dir, "config1")
        path2 = osp.join(rw_dir, "config2")
        template = '[includeIf "{}:{}"]\n    path={}\n'

        def include_config(condition, pattern):
            return template.format(
                condition,
                _escape_section_subsection(pattern),
                _escape_config_value(path2),
            )

        with open(path1, "w") as stream:
            stream.write(include_config("gitdir", git_dir))

        # Ensure that config is ignored if no repo is set.
        with GitConfigParser(path1) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

        # Ensure that config is included if path is matching git_dir.
        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

        # Ensure that config is ignored if case is incorrect.
        with open(path1, "w") as stream:
            stream.write(include_config("gitdir", git_dir.upper()))

        with GitConfigParser(path1, repo=repo) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

        # Ensure that config is included if case is ignored.
        with open(path1, "w") as stream:
            stream.write(include_config("gitdir/i", git_dir.upper()))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

        # Ensure that config is included with path using glob pattern.
        with open(path1, "w") as stream:
            stream.write(include_config("gitdir", "**/repo1"))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

        # Ensure that config is ignored if path is not matching git_dir.
        with open(path1, "w") as stream:
            stream.write(include_config("gitdir", "incorrect"))

        with GitConfigParser(path1, repo=repo) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

        # Ensure that config is included if path in hierarchy.
        with open(path1, "w") as stream:
            stream.write(include_config("gitdir", "target1/"))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

    @with_rw_directory
    def test_conditional_includes_from_branch_name(self, rw_dir):
        # Initiate mocked branch.
        branch = mock.Mock()
        type(branch).name = mock.PropertyMock(return_value="/foo/branch")

        # Initiate mocked repository.
        repo = mock.Mock(active_branch=branch)

        # Initiate config files.
        path1 = osp.join(rw_dir, "config1")
        path2 = osp.join(rw_dir, "config2")
        template = '[includeIf "onbranch:{}"]\n    path={}\n'

        # Ensure that config is included is branch is correct.
        with open(path1, "w") as stream:
            stream.write(template.format("/foo/branch", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

        # Ensure that config is included is branch is incorrect.
        with open(path1, "w") as stream:
            stream.write(template.format("incorrect", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

        # Ensure that config is included with branch using glob pattern.
        with open(path1, "w") as stream:
            stream.write(template.format("/foo/**", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

    @with_rw_directory
    def test_conditional_includes_from_branch_name_error(self, rw_dir):
        # Initiate mocked repository to raise an error if HEAD is detached.
        repo = mock.Mock()
        type(repo).active_branch = mock.PropertyMock(side_effect=TypeError)

        # Initiate config file.
        path1 = osp.join(rw_dir, "config1")

        # Ensure that config is ignored when active branch cannot be found.
        with open(path1, "w") as stream:
            stream.write('[includeIf "onbranch:foo"]\n    path=/path\n')

        with GitConfigParser(path1, repo=repo) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

    @with_rw_directory
    def test_conditional_includes_remote_url(self, rw_dir):
        # Initiate mocked repository.
        repo = mock.Mock()
        repo.remotes = [mock.Mock(url="https://github.com/foo/repo")]

        # Initiate config files.
        path1 = osp.join(rw_dir, "config1")
        path2 = osp.join(rw_dir, "config2")
        template = '[includeIf "hasconfig:remote.*.url:{}"]\n    path={}\n'

        # Ensure that config with hasconfig and full url is correct.
        with open(path1, "w") as stream:
            stream.write(template.format("https://github.com/foo/repo", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

        # Ensure that config with hasconfig and incorrect url is incorrect.
        with open(path1, "w") as stream:
            stream.write(template.format("incorrect", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert not config._has_includes()
            assert config._included_paths() == []

        # Ensure that config with hasconfig and url using glob pattern is correct.
        with open(path1, "w") as stream:
            stream.write(template.format("**/**github.com*/**", _escape_config_value(path2)))

        with GitConfigParser(path1, repo=repo) as config:
            assert config._has_includes()
            assert config._included_paths() == [("path", path2)]

    def test_rename(self):
        file_obj = self._to_memcache(fixture_path("git_config"))
        with GitConfigParser(file_obj, read_only=False, merge_includes=False) as cw:
            with self.assertRaises(ValueError):
                cw.rename_section("doesntexist", "foo")
            with self.assertRaises(ValueError):
                cw.rename_section("core", "include")

            nn = "bee"
            assert cw.rename_section("core", nn) is cw
            assert not cw.has_section("core")
            assert len(cw.items(nn)) == 4

    def test_complex_aliases(self):
        file_obj = self._to_memcache(fixture_path(".gitconfig"))
        with GitConfigParser(file_obj, read_only=False) as w_config:
            self.assertEqual(
                w_config.get("alias", "rbi"),
                "!g() { git rebase -i origin/${1:-master} ; } ; g",
            )
        self.assertEqual(
            file_obj.getvalue(),
            self._to_memcache(fixture_path(".gitconfig")).getvalue(),
        )

    def test_config_with_extra_whitespace(self):
        cr = GitConfigParser(fixture_path("git_config_with_extra_whitespace"), read_only=True)
        self.assertEqual(cr.get("init", "defaultBranch"), "trunk")

    def test_empty_config_value(self):
        cr = GitConfigParser(fixture_path("git_config_with_empty_value"), read_only=True)

        assert cr.get_value("core", "filemode"), "Should read keys with values"

        self.assertIs(cr.get_value("color", "ui"), True, "a valueless Git config entry means boolean true")

    def test_config_with_quotes(self):
        cr = GitConfigParser(fixture_path("git_config_with_quotes"), read_only=True)

        self.assertEqual(cr.get("user", "name"), "Cody Veal")
        self.assertEqual(cr.get("user", "email"), "cveal05@gmail.com")

    def test_config_with_empty_quotes(self):
        cr = GitConfigParser(fixture_path("git_config_with_empty_quotes"), read_only=True)
        self.assertEqual(cr.get("core", "filemode"), "", "quotes can form a literal empty string as value")

    def test_config_with_quotes_with_literal_whitespace(self):
        cr = GitConfigParser(fixture_path("git_config_with_quotes_whitespace_inside"), read_only=True)
        self.assertEqual(cr.get("core", "commentString"), "# ")

    def test_config_with_quotes_with_whitespace_outside_value(self):
        cr = GitConfigParser(fixture_path("git_config_with_quotes_whitespace_outside"), read_only=True)
        self.assertEqual(cr.get("init", "defaultBranch"), "trunk")

    def test_config_with_quotes_containing_escapes(self):
        """Interpret the quoted-value escapes supported by Git."""
        cr = GitConfigParser(fixture_path("git_config_with_quotes_escapes"), read_only=True)

        self.assertEqual(cr.get("custom", "hasnewline"), "first\nsecond")
        self.assertEqual(cr.get("custom", "hasbackslash"), R"foo\bar")
        self.assertEqual(cr.get("custom", "hasquote"), 'ab"cd')
        self.assertEqual(cr.get("custom", "hastrailingbackslash"), "word\\")

        # Cases where quote removal is clearly safe should happen even after those.
        self.assertEqual(cr.get("custom", "ordinary"), "hello world")

        # Cases without quotes should still parse correctly even after those, too.
        self.assertEqual(cr.get("custom", "unquoted"), "good evening")

    def test_get_values_works_without_requiring_any_other_calls_first(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        cr = GitConfigParser(file_obj, read_only=True)
        self.assertEqual(cr.get_values("section0", "option0"), ["value0"])
        file_obj.seek(0)
        cr = GitConfigParser(file_obj, read_only=True)
        self.assertEqual(cr.get_values("section1", "option1"), ["value1a", "value1b"])
        file_obj.seek(0)
        cr = GitConfigParser(file_obj, read_only=True)
        self.assertEqual(cr.get_values("section1", "other-option1"), ["other_value1"])

    def test_multiple_values(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        with GitConfigParser(file_obj, read_only=False) as cw:
            self.assertEqual(cw.get("section0", "option0"), "value0")
            self.assertEqual(cw.get_values("section0", "option0"), ["value0"])
            self.assertEqual(cw.items("section0"), [("option0", "value0")])

            # Where there are multiple values, "get" returns the last.
            self.assertEqual(cw.get("section1", "option1"), "value1b")
            self.assertEqual(cw.get_values("section1", "option1"), ["value1a", "value1b"])
            self.assertEqual(
                cw.items("section1"),
                [("option1", "value1b"), ("other-option1", "other_value1")],
            )
            self.assertEqual(
                cw.items_all("section1"),
                [
                    ("option1", ["value1a", "value1b"]),
                    ("other-option1", ["other_value1"]),
                ],
            )
            with self.assertRaises(KeyError):
                cw.get_values("section1", "missing")

            self.assertEqual(cw.get_values("section1", "missing", 1), [1])
            self.assertEqual(cw.get_values("section1", "missing", "s"), ["s"])

    def test_multiple_values_rename(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        with GitConfigParser(file_obj, read_only=False) as cw:
            cw.rename_section("section1", "section2")
            cw.write()
            file_obj.seek(0)
            cr = GitConfigParser(file_obj, read_only=True)
            self.assertEqual(cr.get_value("section2", "option1"), "value1b")
            self.assertEqual(cr.get_values("section2", "option1"), ["value1a", "value1b"])
            self.assertEqual(
                cr.items("section2"),
                [("option1", "value1b"), ("other-option1", "other_value1")],
            )
            self.assertEqual(
                cr.items_all("section2"),
                [
                    ("option1", ["value1a", "value1b"]),
                    ("other-option1", ["other_value1"]),
                ],
            )

    def test_multiple_to_single(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        with GitConfigParser(file_obj, read_only=False) as cw:
            cw.set_value("section1", "option1", "value1c")

            cw.write()
            file_obj.seek(0)
            cr = GitConfigParser(file_obj, read_only=True)
            self.assertEqual(cr.get_value("section1", "option1"), "value1c")
            self.assertEqual(cr.get_values("section1", "option1"), ["value1c"])
            self.assertEqual(
                cr.items("section1"),
                [("option1", "value1c"), ("other-option1", "other_value1")],
            )
            self.assertEqual(
                cr.items_all("section1"),
                [("option1", ["value1c"]), ("other-option1", ["other_value1"])],
            )

    def test_single_to_multiple(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        with GitConfigParser(file_obj, read_only=False) as cw:
            cw.add_value("section1", "other-option1", "other_value1a")

            cw.write()
            file_obj.seek(0)
            cr = GitConfigParser(file_obj, read_only=True)
            self.assertEqual(cr.get_value("section1", "option1"), "value1b")
            self.assertEqual(cr.get_values("section1", "option1"), ["value1a", "value1b"])
            self.assertEqual(cr.get_value("section1", "other-option1"), "other_value1a")
            self.assertEqual(
                cr.get_values("section1", "other-option1"),
                ["other_value1", "other_value1a"],
            )
            self.assertEqual(
                cr.items("section1"),
                [("option1", "value1b"), ("other-option1", "other_value1a")],
            )
            self.assertEqual(
                cr.items_all("section1"),
                [
                    ("option1", ["value1a", "value1b"]),
                    ("other-option1", ["other_value1", "other_value1a"]),
                ],
            )

    def test_add_to_multiple(self):
        file_obj = self._to_memcache(fixture_path("git_config_multiple"))
        with GitConfigParser(file_obj, read_only=False) as cw:
            cw.add_value("section1", "option1", "value1c")
            cw.write()
            file_obj.seek(0)
            cr = GitConfigParser(file_obj, read_only=True)
            self.assertEqual(cr.get_value("section1", "option1"), "value1c")
            self.assertEqual(cr.get_values("section1", "option1"), ["value1a", "value1b", "value1c"])
            self.assertEqual(
                cr.items("section1"),
                [("option1", "value1c"), ("other-option1", "other_value1")],
            )
            self.assertEqual(
                cr.items_all("section1"),
                [
                    ("option1", ["value1a", "value1b", "value1c"]),
                    ("other-option1", ["other_value1"]),
                ],
            )

    def test_parser_uses_git_native_storage(self):
        self.assertFalse(issubclass(GitConfigParser, cp.RawConfigParser))

    @with_rw_directory
    def test_valueless_entries_remain_distinct_from_literal_true(self, rw_dir):
        config_path = osp.join(rw_dir, "config")
        with open(config_path, "wb") as config_file:
            config_file.write(b'[Feature]\n\tImplicit\n\tExplicit = "true"\n')

        with GitConfigParser(config_path, read_only=False) as git_config:
            self.assertIs(git_config.get_value("feature", "implicit"), True)
            self.assertIs(git_config.get_value("FEATURE", "EXPLICIT"), True)
            git_config.set_value("feature", "Other", "value")

        with open(config_path, "rb") as config_file:
            self.assertEqual(
                config_file.read(),
                b'[Feature]\n\tImplicit\n\tExplicit = "true"\n\tOther = "value"\n',
            )

    def test_git_typed_accessors(self):
        config_file = io.BytesIO(b"[values]\nsize = 2k\nratio = 1.5m\nyes = on\nno = 0\nimplicit\n")
        config_file.name = "typed-values.config"
        git_config = GitConfigParser(config_file)

        self.assertEqual(git_config.getint("VALUES", "SIZE"), 2048)
        self.assertEqual(git_config.getfloat("values", "ratio"), 1.5 * 1024**2)
        self.assertIs(git_config.getboolean("values", "yes"), True)
        self.assertIs(git_config.getboolean("values", "no"), False)
        self.assertIs(git_config.getboolean("values", "implicit"), True)
