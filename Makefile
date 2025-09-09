.PHONY: build

build: | dep-zig
	zig build -Drelease=true


.PHONY: deps dep-zig dep-npm
deps: dep-zig dep-npm node_modules

dep-zig:
	@zig version 2>&1 | grep '0\.14\.[0-9]' 2>&1 >/dev/null || ( \
		echo 'Zig v0.14.* required' >&2 ; \
		exit 1 ; \
	)

dep-npm:
	@npm --version 2>&1 >/dev/null || ( \
		echo 'NPM required' >&2 ; \
		exit 1 ; \
	)

node_modules: package.json package-lock.json | dep-npm
	npm ci

