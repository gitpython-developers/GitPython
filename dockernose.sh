#!/usr/bin/env bash
set -ex
if [ -z "${PYVER}" ]; then
    PYVER=py37
fi

# remember to use "-s" if you inject pdb.set_trace() as this disables nosetests capture of streams

tox -e ${PYVER} --notest
PYTHONPATH=/src/.tox/${PYVER}/lib/python*/site-packages /src/.tox/${PYVER}/bin/nosetests --pdb $*
