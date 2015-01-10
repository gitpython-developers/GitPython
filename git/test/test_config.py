# test_config.py
# Copyright (C) 2008, 2009 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

from git.test.lib import (
    TestCase,
    fixture_path,
    assert_equal
)
from git import (
    GitConfigParser
)
from git.compat import (
    string_types,
)
import io
from copy import copy
from git.config import cp


class TestBase(TestCase):

    def _to_memcache(self, file_path):
        fp = open(file_path, "rb")
        sio = io.BytesIO(fp.read())
        sio.name = file_path
        return sio

    def _parsers_equal_or_raise(self, lhs, rhs):
        pass

    def test_read_write(self):
        # writer must create the exact same file as the one read before
        for filename in ("git_config", "git_config_global"):
            file_obj = self._to_memcache(fixture_path(filename))
            file_obj_orig = copy(file_obj)
            w_config = GitConfigParser(file_obj, read_only=False)
            w_config.read()                 # enforce reading
            assert w_config._sections
            w_config.write()                # enforce writing

            # we stripped lines when reading, so the results differ
            assert file_obj.getvalue() and file_obj.getvalue() != file_obj_orig.getvalue()

            # creating an additional config writer must fail due to exclusive access
            self.failUnlessRaises(IOError, GitConfigParser, file_obj, read_only=False)

            # should still have a lock and be able to make changes
            assert w_config._lock._has_lock()

            # changes should be written right away
            sname = "my_section"
            oname = "mykey"
            val = "myvalue"
            w_config.add_section(sname)
            assert w_config.has_section(sname)
            w_config.set(sname, oname, val)
            assert w_config.has_option(sname, oname)
            assert w_config.get(sname, oname) == val

            sname_new = "new_section"
            oname_new = "new_key"
            ival = 10
            w_config.set_value(sname_new, oname_new, ival)
            assert w_config.get_value(sname_new, oname_new) == ival

            file_obj.seek(0)
            r_config = GitConfigParser(file_obj, read_only=True)
            assert r_config.has_section(sname)
            assert r_config.has_option(sname, oname)
            assert r_config.get(sname, oname) == val
        # END for each filename

    def test_multi_line_config(self):
        file_obj = self._to_memcache(fixture_path("git_config_with_comments"))
        config = GitConfigParser(file_obj, read_only=False)
        ev = "ruby -e '\n"
        ev += "		system %(git), %(merge-file), %(--marker-size=%L), %(%A), %(%O), %(%B)\n"
        ev += "		b = File.read(%(%A))\n"
        ev += "		b.sub!(/^<+ .*\\nActiveRecord::Schema\\.define.:version => (\\d+). do\\n=+\\nActiveRecord::Schema\\."
        ev += "define.:version => (\\d+). do\\n>+ .*/) do\n"
        ev += "		  %(ActiveRecord::Schema.define(:version => #{[$1, $2].max}) do)\n"
        ev += "		end\n"
        ev += "		File.open(%(%A), %(w)) {|f| f.write(b)}\n"
        ev += "		exit 1 if b.include?(%(<)*%L)'"
        assert_equal(config.get('merge "railsschema"', 'driver'), ev)
        assert_equal(config.get('alias', 'lg'),
                     "log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr)%Creset'"
                     " --abbrev-commit --date=relative")
        assert len(config.sections()) == 23

    def test_base(self):
        path_repo = fixture_path("git_config")
        path_global = fixture_path("git_config_global")
        r_config = GitConfigParser([path_repo, path_global], read_only=True)
        assert r_config.read_only
        num_sections = 0
        num_options = 0

        # test reader methods
        assert r_config._is_initialized is False
        for section in r_config.sections():
            num_sections += 1
            for option in r_config.options(section):
                num_options += 1
                val = r_config.get(section, option)
                val_typed = r_config.get_value(section, option)
                assert isinstance(val_typed, (bool, int, float, ) + string_types)
                assert val
                assert "\n" not in option
                assert "\n" not in val

                # writing must fail
                self.failUnlessRaises(IOError, r_config.set, section, option, None)
                self.failUnlessRaises(IOError, r_config.remove_option, section, option)
            # END for each option
            self.failUnlessRaises(IOError, r_config.remove_section, section)
        # END for each section
        assert num_sections and num_options
        assert r_config._is_initialized is True

        # get value which doesnt exist, with default
        default = "my default value"
        assert r_config.get_value("doesnt", "exist", default) == default

        # it raises if there is no default though
        self.failUnlessRaises(cp.NoSectionError, r_config.get_value, "doesnt", "exist")
