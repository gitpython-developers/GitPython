.PHONY: all clean release force_release

all:
	@grep -Ee '^[a-z].*:' Makefile | cut -d: -f1 | grep -vF all

clean:
	rm -rf build/ dist/ .eggs/ .tox/

release: clean
	# Check if latest tag is the current head we're releasing
	@config_opts="$$(printf ' -c versionsort.suffix=-%s' alpha beta pre rc RC)" && \
	latest_tag=$$(git $$config_opts tag -l '[0-9]*' --sort=-v:refname | head -n1) && \
	head_sha=$$(git rev-parse HEAD) latest_tag_sha=$$(git rev-parse "$$latest_tag") && \
	printf '%-14s = %s\n' 'Latest tag'     "$$latest_tag" \
	                      'HEAD SHA'       "$$head_sha" \
	                      'Latest tag SHA' "$$latest_tag_sha" && \
	test "$$head_sha" = "$$latest_tag_sha"

	make force_release

force_release: clean
	# IF we're in a virtual environment, add build tools
	test -z "$$VIRTUAL_ENV" || pip install -U build twine
	python3 -m build --sdist --wheel || echo "Use a virtual-env with 'python -m venv env && source env/bin/activate' instead"
	twine upload dist/*
	git push --tags origin main
