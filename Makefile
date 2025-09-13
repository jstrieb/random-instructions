ZIG_ARGS =

.PHONY: build graphs deps

build: zig-out/bin/random_instructions

zig-out/bin/random_instructions: build.zig src/main.zig | dep-zig
	zig build -Drelease=true $(ZIG_ARGS)
	-@touch zig-out/bin/random_instructions

graphs: $(patsubst %.vl.json,%.svg,$(wildcard graphs/*.vl.json))

graphs/%.svg: graphs/%.vl.json graphs/thresholds.csv | node_modules
	npx vl2svg "$<" "$@"


.PHONY: dep-zig dep-npm
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

