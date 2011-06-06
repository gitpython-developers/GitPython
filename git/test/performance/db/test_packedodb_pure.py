from packedodb_impl import TestPurePackedODBPerformanceBase
from git.db.py.pack import PurePackedODB

class TestPurePackedODB(TestPurePackedODBPerformanceBase):
	#{ Configuration
	PackedODBCls = PurePackedODB
	#} END configuration
