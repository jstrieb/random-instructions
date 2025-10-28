ZIG_ARGS =

.PHONY: build graphs deps

graphs: $(patsubst %.vl.json,%.svg,$(wildcard graphs/*.vl.json))

build: zig-out/bin/random_instructions zig-out/bin/random_inflate

zig-out/bin/random_instructions zig-out/bin/random_inflate: build.zig src/*.zig | dep-zig
	zig build -Drelease=true $(ZIG_ARGS)
	-@touch "$@"

graphs/%.svg: graphs/%.vl.json graphs/*.csv | node_modules
	npx vl2svg "$<" "$@"

graphs/totals.csv: zig-out/bin/random_instructions
	time ./zig-out/bin/random_instructions \
		--total-iterations 1_000_000_000 \
		--disassembly-threshold 95 \
		--csv \
	| tee "$@"

graphs/thresholds.csv: zig-out/bin/random_instructions
	printf '%s\r\n' 'Type,Count,Size,Threshold,Architecture,Mode' > "$@"
	( \
		for SIZE in 2 4 8 16 32 64 128 256 512 1024; do \
			for THRESHOLD in $$(seq 100 -5 60); do \
				time ./zig-out/bin/random_instructions \
					--total-iterations 1_000_000_000 \
					--disassembly-threshold "$${THRESHOLD}" \
					--buffer-size "$${SIZE}" \
					--csv \
					--no-csv-header ; \
			done ; \
		done \
	) | tee -a "$@"

graphs/architectures.csv: zig-out/bin/random_instructions
	printf '%s\r\n' 'Type,Count,Size,Threshold,Architecture,Mode' > "$@"
	( \
		for SIZE in 2 4 8 16 32 64 128 256 512 1024; do \
			for THRESHOLD in $$(seq 100 -5 70); do \
				time ./zig-out/bin/random_instructions \
					--total-iterations 1_000_000_000 \
					--disassembly-threshold "$${THRESHOLD}" \
					--buffer-size "$${SIZE}" \
					--csv \
					--no-csv-header \
					--all-architectures ; \
			done ; \
		done \
	) | tee -a "$@"

graphs/inflate.csv: zig-out/bin/random_inflate
	time ./zig-out/bin/random_inflate --total-iterations 1_000_000_000 \
		| tee "$@"
	( \
		for I in $$(seq 0 7); do \
			time ./zig-out/bin/random_inflate \
				--total-iterations 1_000_000_000 \
				--no-csv-header \
				--num-bits 3 \
				--first-bits "$${I}" ; \
		done \
	) | tee -a "$@"

graphs/inflate_1_bit.csv: zig-out/bin/random_inflate
	time ./zig-out/bin/random_inflate \
			--total-iterations 1_000_000_000 \
			--first-bits 0b0 \
			--num-bits 1 \
		| tee "$@"
	time ./zig-out/bin/random_inflate \
			--total-iterations 1_000_000_000 \
			--first-bits 0b1 \
			--num-bits 1 \
		| tee -a "$@"


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

