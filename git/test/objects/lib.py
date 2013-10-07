"""Provide customized obhject testing facilities"""

from git.test.lib import (
							rorepo_dir,
							TestBase,
							assert_equal,
							assert_not_equal,
							with_rw_repo,
							StringProcessAdapter,
                                                        fixture_path,
						)

class TestObjectBase(TestBase):
	"""Provides a default read-only repository in the rorepo member"""
	pass
