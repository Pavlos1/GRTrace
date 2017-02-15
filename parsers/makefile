CC  := gcc
SRC := $(shell\
    find . -maxdepth 1 -type f -regextype sed -regex ".*\(\.c\|\.S\)")
EXC := $(patsubst %.S,bin/%,$(patsubst %.c,bin/%,$(SRC)))

bin/%: %.c
	$(CC) $^ -o $@

bin/%: %.S
	$(CC) -nostdlib $^ -o $@

all: default

default: $(EXC)

clean:
	rm -f bin/*
