.text
.global _start

_start:
    # Get argv[1] into %rdi and call sys_open
    popq %rcx
    cmpq $2, %rcx
    jne exit_failure

    addq $8, %rsp
    popq %rdi

    movq $2, %rax # open
    movq $0, %rsi # O_RDONLY
    syscall

    cmpq $0, %rax
    jl exit_failure
    movq %rax, fd

    # Load first four bytes into v1->v4
    movq $0, %rax
    movq fd, %rdi
    lea  v1, %rsi
    movq $4, %rdx
    syscall

    # Use REPNZ.MOVSB to copy (v1->v4) in to (v5->v8)
    lea v1,  %rsi # source
    lea v5,  %rdi # destination
    cld           # low -> high
    movq $4, %rcx # 4 times
    repnz movsb

    # Close the file
    movq $3, %rax
    movq fd, %rdi
    syscall

exit_success:
    movq $60, %rax
    movq $0, %rdi
    syscall
exit_failure:
    movq $60, %rax
    movq $1, %rdi
    syscall

.data
fd: .skip 8
v1: .skip 1
v2: .skip 1
v3: .skip 1
v4: .skip 1
v5: .skip 1
v6: .skip 1
v7: .skip 1
v8: .skip 1
