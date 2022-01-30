PROJ := portable8439

CFLAGS ?= -O3
CFLAGS += -std=c99 -Wpedantic -Wall -Wextra -Isrc -Isrc/chacha-portable -Isrc/poly1305-donna -fstack-protector
LDFLAGS :=
VERSION ?= dev-version
PREFIX ?= /usr/local

SRCDIR := src
BLDDIR := dist
TSTDIR := $(BLDDIR)/test

SOURCES := $(shell find $(SRCDIR) -type f -iname '*.c')
TESTSRC := $(filter-out test/bench.c, $(wildcard test/*.c))
TESTBIN := $(patsubst test%, $(TSTDIR)%, $(patsubst %.c, %, $(TESTSRC)))

MKDIR := mkdir -p --
RM := rm -rf --

.PHONY: all clean check install simple release uninstall

all: $(BLDDIR)/lib$(PROJ).so $(BLDDIR)/lib$(PROJ).a $(BLDDIR)/$(PROJ).c

clean:
	$(RM) $(BLDDIR)

check: $(TESTBIN) $(TSTDIR)/algamized-test
	for i in $^; do ./$$i; done

$(BLDDIR)/lib$(PROJ).so: $(BLDDIR)/$(PROJ).c
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -shared $^ -o $@ $(LDFLAGS)

$(BLDDIR)/lib$(PROJ).a: $(BLDDIR)/$(PROJ).c
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -c $< -o $(<:.c=.o)
	$(AR) rcs $@ $(<:.c=.o)

simple: $(BLDDIR)/$(PROJ).c

$(BLDDIR)/$(PROJ).h: $(BLDDIR)/$(PROJ).c

$(BLDDIR)/$(PROJ).c:
	$(MKDIR) $(@D)
	bash ./algamize.sh $(BLDDIR) "$(VERSION)"

$(TSTDIR)/%: $(SOURCES) test/%.c
	$(MKDIR) $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TSTDIR)/algamized-test: test/algamized-test.go | $(BLDDIR)/$(PROJ).c
	cd test; go build -o ../$@ ../$<

release: $(BLDDIR)/$(PROJ)-$(VERSION).zip

$(BLDDIR)/$(PROJ)-$(VERSION).zip: all
	cp -a $(BLDDIR) $(PROJ)-$(VERSION)
	cp LICENSE $(PROJ)-$(VERSION)
	cp README.md $(PROJ)-$(VERSION)
	$(RM) $(PROJ)-$(VERSION)/obj
	zip -r -9 -X $@ $(PROJ)-$(VERSION)
	$(RM) $(PROJ)-$(VERSION)

install: all
	install -Dm755 $(BLDDIR)/lib$(PROJ).so $(DESTDIR)$(PREFIX)/lib/lib$(PROJ).so
	install -Dm755 $(BLDDIR)/lib$(PROJ).a $(DESTDIR)$(PREFIX)/lib/lib$(PROJ).a
	install -Dm755 $(BLDDIR)/$(PROJ).h $(DESTDIR)$(PREFIX)/include/$(PROJ).h

uninstall:
	 rm -f -- $(DESTDIR)$(PREFIX)/lib/lib$(PROJ).so \
	 	$(DESTDIR)$(PREFIX)/lib/lib$(PROJ).a \
	 	$(DESTDIR)$(PREFIX)/include/$(PROJ).h

$(V).SILENT:
