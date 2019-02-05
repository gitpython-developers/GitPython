#!/usr/bin/env bash
set -ex
if [ -z "${PYVER}" ]; then
    PYVER=py37
fi

tox -e ${PYVER} --notest
PYTHONPATH=/src/.tox/${PYVER}/lib/python*/site-packages /src/.tox/${PYVER}/bin/nosetests --pdb $*
