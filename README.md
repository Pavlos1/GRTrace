# GRTrace
## TODO: Think of better title

A utility for producing a GRIST-compatible parse trace by instrumenting an
x86 binary with Intel's PIN tool.

To run the parser, first download and extract the latest PIN toolkit to
GRTrace's parent directory. Then, run:

```bash
./make
./run
```

This will trace the execution of ghostscript on a sample PDF file.
Alternatively, you can specify the parser and input file.

```bash
./run $PARSER $FILE
# e.g.
./run parsers/bin/asm_branch_taint tests/pdf_valid.pdf
```
