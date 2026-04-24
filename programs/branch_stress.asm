.data
signature: .word 0x00000000
scratch:   .space 16

.text
.globl main
main:
    # Static branch-prediction/recovery stress. Conditional branches are
    # predicted not-taken; taken branches exercise frontend recovery.
    addi $2, $0, 0
    addi $3, $0, 1
    beq  $2, $3, taken_a  # not taken, prediction correct
    addi $4, $0, 5

    beq  $3, $3, taken_a  # taken, prediction miss and recovery
    addi $4, $0, 99       # must be flushed
    nop
    nop

taken_a:
    addi $5, $4, 7        # 12
    bne  $5, $4, taken_b  # taken, prediction miss and recovery
    addi $6, $0, 99       # must be flushed
    nop

taken_b:
    addi $6, $5, 1        # 13
    la   $7, signature
    sw   $6, 0($7)

end:
    j end
    nop
    nop
    nop
