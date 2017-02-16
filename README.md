# GRTrace
## TODO: Think of better title

A utility for producing a taint trace by instrumenting an x86 binary
with Intel's PIN tool. Presented at the Fifth Trustworthy Systems
Summer School (Sydney, 13-14 Feb).

The poster and presentation slides can be found under TSSummerSchool/.

To run the taint tracer, first download and extract the latest PIN toolkit to
GRTrace's parent directory. Do not rename the extracted folder. Then, run:

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
