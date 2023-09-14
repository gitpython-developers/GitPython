.PHONY: all clean release force_release

all:
	@grep -Ee '^[a-z].*:' Makefile | cut -d: -f1 | grep -vF all

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	./check-version.sh
	make force_release

force_release: clean
	# IF we're in a virtual environment, add build tools
	test -z "$$VIRTUAL_ENV" || pip install -U build twine

	# Build the sdist and wheel that will be uploaded to PyPI.
	if test -n "$$VIRTUAL_ENV"; then \
		python -m build --sdist --wheel; \
	else \
		python3 -m build --sdist --wheel || \
		{ echo "Use a virtual-env with 'python -m venv env && source env/bin/activate' instead" && false; }; \
	fi

	# Upload to PyPI and push the tag.
	twine upload dist/*
	git push --tags origin main
