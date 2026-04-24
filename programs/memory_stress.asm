.data
signature: .word 0x00000000
scratch:   .space 16
values:    .word 0x00000001, 0x00000002, 0x00000003, 0x00000004, 0x00000000

.text
.globl main
main:
    # Memory hierarchy / encrypted data path stress: several loads, one store,
    # then a reload of the stored value.
    la   $2, values
    lw   $3, 0($2)       # 1
    lw   $4, 4($2)       # 2
    lw   $5, 8($2)       # 3
    lw   $6, 12($2)      # 4
    add  $7, $3, $4      # 3
    add  $8, $5, $6      # 7
    add  $9, $7, $8      # 10
    sw   $9, 16($2)
    lw   $10, 16($2)     # 10
    la   $11, signature
    sw   $10, 0($11)
    nop
    nop

end:
    j end
    nop
    nop
    nop
