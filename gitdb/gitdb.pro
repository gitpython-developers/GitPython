
OTHER_FILES += \
    setup.py \
    README.rst \
    MANIFEST \
    Makefile \
    LICENSE \
    AUTHORS \
    gitdb/util.py \
    gitdb/typ.py \
    gitdb/stream.py \
    gitdb/pack.py \
    gitdb/__init__.py \
    gitdb/fun.py \
    gitdb/exc.py \
    gitdb/base.py \
    doc/source/tutorial.rst \
    doc/source/intro.rst \
    doc/source/index.rst \
    doc/source/conf.py \
    doc/source/changes.rst \
    doc/source/api.rst \
    doc/source/algorithm.rst \
    gitdb/db/ref.py \
    gitdb/db/pack.py \
    gitdb/db/mem.py \
    gitdb/db/loose.py \
    gitdb/db/__init__.py \
    gitdb/db/git.py \
    gitdb/db/base.py \
    gitdb/test/test_util.py \
    gitdb/test/test_stream.py \
    gitdb/test/test_pack.py \
    gitdb/test/test_example.py \
    gitdb/test/test_base.py \
    gitdb/test/lib.py \
    gitdb/test/__init__.py \
    gitdb/test/performance/test_stream.py \
    gitdb/test/performance/test_pack_streaming.py \
    gitdb/test/performance/test_pack.py \
    gitdb/test/performance/lib.py

HEADERS += \
    gitdb/_delta_apply.h

SOURCES += \
    gitdb/_fun.c \
    gitdb/_delta_apply.c
