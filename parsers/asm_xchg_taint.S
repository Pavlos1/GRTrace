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

    # Read 0->v1, 1->v2
    movq $0, %rax
    movq fd, %rdi
    lea  v1, %rsi
    movq $1, %rdx
    syscall

    movq $0, %rax
    movq fd, %rdi
    lea  v2, %rsi
    movq $1, %rdx
    syscall

    # Test register exchange
    movb v1, %r10b
    movb v2, %r11b
    xchg %r10, %r11

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
