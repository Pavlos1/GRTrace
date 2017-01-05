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

    # Test offset-based tainting
    xor %r10, %r10
    xor %r11, %r11
    movb v2, %r10b
    movb v1, %r11b
    lea padding, %r12
    add %r10, %r12
    xor %r10, %r10
    movb %r11b, (%r12)
    xor %r12, %r12
    xor %r11, %r11

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
padding: .skip 4096
