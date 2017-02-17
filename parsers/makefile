CC  := gcc

SRC := $(shell ls | grep "\(\.c\|.S\)$$" | grep -v "^bin$$" \
	| grep -v "^verify_mupdf.c$$")

EXC := $(patsubst %.S,bin/%,$(patsubst %.c,bin/%,$(SRC)))

all: default

default: $(EXC)

clean:
	rm -f bin/*

bin/verify_mupdf: verify_mupdf.c
	$(CC) $^ -o $@ -lmupdf -lfreetype -ljbig2dec -ljpeg -lopenjpeg \
		-lz -lcrypto -lm -lharfbuzz

bin/%: %.c
	$(CC) $^ -o $@

bin/%: %.S
	$(CC) -nostdlib $^ -o $@
