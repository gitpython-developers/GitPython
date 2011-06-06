from git.db.py.loose import PureLooseObjectODB
from looseodb_impl import TestLooseDBWPerformanceBase

class TestPureLooseDB(TestLooseDBWPerformanceBase):
	LooseODBCls = PureLooseObjectODB
	
