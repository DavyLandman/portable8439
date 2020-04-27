.PHONY: clean test dist test-dist

src = $(wildcard src/*.c) $(wildcard src/chacha-portable/*.c) $(wildcard src/poly1305-donna/*.c)

CFLAGS?=-O3
CFLAGS+=-std=c99 -pedantic -Wall -Wextra -Isrc -Isrc/chacha-portable -Isrc/poly1305-donna
LDFLAGS = 

VERSION?=dev-version

bin/test-vectors: $(src) test/test-vectors.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)


bin/test-roundtrip: $(src) test/roundtrip.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

bin/bench: $(src) test/bench.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

test: bin/test-roundtrip bin/test-vectors
	./bin/test-vectors
	./bin/test-roundtrip

clean:
	rm -f bin/*


bench: bin/bench
	./bin/bench


unused: $(src) test/test-roundtrip.c
	$(CC) -o bin/unused $^ $(LDFLAGS) $(CFLAGS) -ffunction-sections -fdata-sections -Wl,--gc-sections,--print-gc-sections

test-windows: 
	docker run --rm -v "/$(PWD):/app" silkeh/clang bash -c 'cd /app && CC=clang CFLAGS="-fsanitize=undefined -O3" make clean test'

bench-windows:
	docker run --rm -v "/$(PWD):/app" silkeh/clang bash -c 'cd /app && CC=clang CFLAGS="-O3" make clean bench'


test-linux: test test-dist