.PHONY: clean test dist test-dist

src = $(wildcard src/*.c) $(wildcard src/chacha-portable/*.c) $(wildcard src/poly1305-donna/*.c)

CFLAGS?=-O3
CFLAGS+=-std=c99 -pedantic -Wall -Wextra -Isrc -Isrc/chacha-portable -Isrc/poly1305-donna -fstack-protector
LDFLAGS = 

VERSION?=dev-version

bin/test-vectors: $(src) test/test-vectors.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)


dist:
	bash algamize.sh dist/ "${VERSION}"
	cp README.md dist/
	cp LICENSE dist/

bin/test-roundtrip: $(src) test/roundtrip.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

bin/bench: $(src) test/bench.c
	mkdir -p bin
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

test: bin/test-roundtrip bin/test-vectors
	./bin/test-vectors
	./bin/test-roundtrip


test-dist: test/algamized-test.go dist
	cd test && go run algamized-test.go


clean:
	rm -f bin/*


bench: bin/bench
	./bin/bench


test-linux: test test-dist