.PHONY: all clean release force_release

all:
	@grep -Ee '^[a-z].*:' Makefile | cut -d: -f1 | grep -vF all

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	# Check if latest tag is the current head we're releasing
	echo "Latest tag = $$(git tag -l '[0-9]*' --sort=-v:refname | head -n1)"
	echo "HEAD SHA       = $$(git rev-parse HEAD)"
	echo "Latest tag SHA = $$(git tag -l '[0-9]*' --sort=-v:refname | head -n1 | xargs git rev-parse)"
	@test "$$(git rev-parse HEAD)" = "$$(git tag -l '[0-9]*' --sort=-v:refname | head -n1 | xargs git rev-parse)"
	make force_release

force_release: clean
	# IF we're in a virtual environment, add build tools
	test -z "$$VIRTUAL_ENV" || pip install -U build twine
	python3 -m build --sdist --wheel || echo "Use a virtual-env with 'python -m venv env && source env/bin/activate' instead"
	twine upload dist/*
	git push --tags origin main
