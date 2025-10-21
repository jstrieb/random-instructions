ZIG_ARGS =

.PHONY: build graphs deps

build: zig-out/bin/random_instructions zig-out/bin/random_inflate

zig-out/bin/random_instructions zig-out/bin/random_inflate: build.zig src/*.zig | dep-zig
	zig build -Drelease=true $(ZIG_ARGS)
	-touch "$@"

graphs: $(patsubst %.vl.json,%.svg,$(wildcard graphs/*.vl.json))

graphs/%.svg: graphs/%.vl.json graphs/*.csv | node_modules
	npx vl2svg "$<" "$@"

graphs/inflate.csv: zig-out/bin/random_inflate
	time ./zig-out/bin/random_inflate --total-iterations 1_000_000_000 \
		| tee graphs/inflate.csv
	( \
		for I in $$(seq 0 7); do \
			time ./zig-out/bin/random_inflate \
				--total-iterations 1_000_000_000 \
				--no-csv-header \
				--first-three-bits "$${I}" ; \
		done \
	) | tee -a graphs/inflate.csv


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

