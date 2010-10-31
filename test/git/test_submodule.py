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
        raise Exception('we are here')
        _p = tempfile.mkdtemp()
        self.base_path = _p
        demo_repos_file = fixture_path('sample_tree_of_repos_v2.zip')
        zipfile.ZipFile(demo_repos_file).extractall(_p)
        self.bare_repo = Repo(os.path.join(_p, 'reposbase' ,'projects', 'demorepoone'))
        self.repo = Repo(os.path.join(_p, 'reposbase' ,'users', 'joe', 'copy_demorepoone'))

    def tearDown(self):
        shutil.rmtree(self.base_path, True)

    def test_submodule_attributes(self):
        t = self.repo.commit('3408e8f7720eff4a1fd16e9bf654332036c39bf8').tree
        tb = self.bare_repo.commit('3408e8f7720eff4a1fd16e9bf654332036c39bf8').tree
        t_s1 = t['somesubmodule']
        tb_s1 = t['somesubmodule']
        t_s2 = t['somefolder']['nestedmodule']
        tb_s2 = t['somefolder']['nestedmodule']

        self.assertEqual(t_s1.id, '74bc53cdcfd1804b9c3d1afad4db0999931a025c')
        self.assertEqual(tb_s1.id, '74bc53cdcfd1804b9c3d1afad4db0999931a025c')
        self.assertEqual(t_s2.id, '08a4dca6a06e2f8893a955d757d505f0431321cb')
        self.assertEqual(tb_s2.id, '08a4dca6a06e2f8893a955d757d505f0431321cb')
        self.assertEqual(t_s1.name, 'somesubmodule')
        self.assertEqual(tb_s1.name, 'somesubmodule')
        self.assertEqual(t_s2.name, 'nestedmodule')
        self.assertEqual(tb_s2.name, 'nestedmodule')
        self.assertEqual(t_s1.path, '/somesubmodule')
        self.assertEqual(tb_s1.path, '/somesubmodule')
        self.assertEqual(t_s2.path, '/somefolder/nestedmodule')
        self.assertEqual(tb_s2.path, '/somefolder/nestedmodule')
        self.assertEqual(t_s1.url, 'git://gitorious.org/git_http_backend_py/git_http_backend_py.git')
        self.assertEqual(tb_s1.url, 'git://gitorious.org/git_http_backend_py/git_http_backend_py.git')
        self.assertEqual(t_s2.url, 'git://gitorious.org/git_http_backend_py/git_http_backend_py.git')
        self.assertEqual(tb_s2.url, 'git://gitorious.org/git_http_backend_py/git_http_backend_py.git')

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(
        unittest.TestSuite([
            unittest.TestLoader().loadTestsFromTestCase(test_Submodule),
        ])
    )
