.data
signature:   .word 0x00000000
scratch:     .space 16
values:      .word 0x00000001, 0x00000002, 0x00000003, 0x00000004

.text
.globl main
main:
    # Build a deterministic result with different expected value than demo.asm.
    addi $2, $0, 5
    addi $3, $0, 9
    addi $4, $0, 12

    sll  $5, $2, 2       # 20
    add  $6, $3, $4      # 21
    add  $7, $5, $6      # 41
    addi $8, $7, 1       # 42 (0x2A)

    la   $9, signature
    sw   $8, 0($9)

    # Pad so the jump target is 4-instruction-block aligned.
    # la expands to two instructions, so only two NOPs are needed here.
    nop
    nop

end:
    j end
    nop
    nop
    nop