.PHONY: all clean release force_release docker-build test nose-pdb

all:
	@grep -Ee '^[a-z].*:' Makefile | cut -d: -f1 | grep -vF all

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	# Check if latest tag is the current head we're releasing
	echo "Latest tag = $$(git tag | sort -nr | head -n1)"
	echo "HEAD SHA       = $$(git rev-parse head)"
	echo "Latest tag SHA = $$(git tag | sort -nr | head -n1 | xargs git rev-parse)"
	@test "$$(git rev-parse head)" = "$$(git tag | sort -nr | head -n1 | xargs git rev-parse)"
	make force_release

force_release: clean
	git push --tags origin master
	python3 setup.py sdist bdist_wheel
	twine upload -s -i byronimo@gmail.com dist/*

docker-build:
	docker build --quiet -t gitpython:xenial -f Dockerfile .

test: docker-build
	# NOTE!!!
	# NOTE!!! If you are not running from master or have local changes then tests will fail
	# NOTE!!!
	docker run --rm -v ${CURDIR}:/src -w /src -t gitpython:xenial tox

nose-pdb: docker-build
	# run tests under nose and break on error or failure into python debugger
	# HINT: set PYVER to "pyXX" to change from the default of py37 to pyXX for nose tests
	docker run --rm --env PYVER=${PYVER} -v ${CURDIR}:/src -w /src -it gitpython:xenial /bin/bash dockernose.sh
