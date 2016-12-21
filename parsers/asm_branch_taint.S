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

    # The actual code
    movq $0, %rax
    movq fd, %rdi
    lea  v1, %rsi
    movq $1, %rdx
    syscall

    cmpb $37, v1
    jne exit_failure
    
    movq $0, %rax
    movq fd, %rdi
    lea  v1, %rsi
    movq $1, %rdx
    syscall

    movb v1, %r10b
    xor %r10, %r10
    movb v1, %r10b
    sub %r10, %r10

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
