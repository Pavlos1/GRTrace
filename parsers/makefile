default: simple_taint.c branch_taint.c asm_branch_taint.S
	mkdir -p bin
	gcc simple_taint.c -o bin/simple_taint
	gcc branch_taint.c -o bin/branch_taint
	gcc -nostdlib asm_branch_taint.S -o bin/asm_branch_taint
	gcc -nostdlib asm_xchg_taint.S -o bin/asm_xchg_taint
