# GRTrace

A utility for producing a taint trace by instrumenting an x86 binary
with Intel's PIN tool. Presented at the Fifth Trustworthy Systems
Summer School (Sydney, 13-14 Feb).

The poster and presentation slides can be found under TSSummerSchool/.

To run the taint tracer, first download and extract the latest PIN toolkit to
GRTrace's parent directory. Do not rename the extracted folder. Install Ghostscript. Then, run:

```bash
./make
./run
```

This will trace the execution of ghostscript on a sample PDF file.
Alternatively, you can specify the parser and input file:

```bash
./run $PARSER $FILE
# e.g.
./run parsers/bin/asm_branch_taint tests/pdf_valid.pdf
```

If you wish to run `parsers/bin/mupdf_verify`, you will need to install
[libmupdf](http://mupdf.com). Also, you will need to compile it separately with
`cd parsers; make bin/verify_mupdf; cd ..` since I make no guarantees about getting it to compile (tested only on Arch Linux).
