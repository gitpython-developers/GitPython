# test_submodule.py
# Copyright (C) 2008-2010 Michael Trier (mtrier@gmail.com) and contributors
#
# This module is part of GitPython and is released under
# the BSD License: http://www.opensource.org/licenses/bsd-license.php

import os.path
import sys

execpath = os.getcwd()
sys.path.append(os.path.join(execpath, 'gitpython\lib'))

import unittest
import tempfile
import shutil
import zipfile

from test.testlib import *
from git import *

class test_Submodule(unittest.TestCase):

    def setUp(self):
        _p = tempfile.mkdtemp()
        demo_repos_file = fixture_path('sample_tree_of_repos_v1.zip')
        zipfile.ZipFile(demo_repos_file).extractall(_p)
        self.base_path = os.path.join(_p, 'reposbase')

    def tearDown(self):
        shutil.rmtree(self.base_path, True)

    def dtest_01_browser_methods(self):
        _m = self._rpc_tree['browser.listdir']
        self.assertEquals(
            _m(''),
            {'path':'/', 'dirs':[{'name':'projects'},{'name':'teams'},{'name':'users'}]}
        )
        self.assertEquals(
            _m('/'),
            {'path':'/', 'dirs':[{'name':'projects'},{'name':'teams'},{'name':'users'}]}
        )
        self.assertEquals(
            _m('\\'),
            {'path':'/', 'dirs':[{'name':'projects'},{'name':'teams'},{'name':'users'}]}
        )
        # crossing fingers and hoping the order is same on all platforms.
        self.assertEquals(
            _m('projects'),
            {'path':'/projects', 'dirs':[
                {'name':'common_files'},
                {'name':'demorepoone','is_git_dir':True},
                {'name':'projectone','is_git_dir':True}
            ]}
        )
        self.assertEquals(
            _m('projects/common_files'),
            {'path':'/projects/common_files', 'dirs':[]}
        )
        # we don't allow seeing files / folders inside repo folders
        self.assertRaises(grm.PathUnfitError, _m, 'projects/demorepoone')
        self.assertRaises(grm.PathUnfitError, _m, 'projects/demorepoone/objects')
        # on top of fobiden, it also does not exist.
        self.assertRaises(grm.PathUnfitError, _m, 'projects/demorepoone/kjhgjg')
        # all these should not exist
        self.assertRaises(grm.PathUnfitError, _m, 'projects/blah')
        self.assertRaises(grm.PathUnfitError, _m, '/blah')
        # we should forbid seeing contents of folders above base path.
        self.assertRaises(grm.PathUnfitError, _m, 'projects/../../../blah')

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite([
            unittest.TestLoader().loadTestsFromTestCase(test_Submodule),
        ])
    )
