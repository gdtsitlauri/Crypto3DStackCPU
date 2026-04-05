.data
# Keep signature at offset 0 from data_start for contract checks.
signature: .word 0
scratch:   .space 64
src0:      .word 0x00000011, 0x00000022, 0x00000033, 0x00000044

.text
.globl main
main:
    # Base deterministic values.
    addi $2, $0, 1
    addi $3, $0, 2
    addi $4, $0, 3
    addi $5, $0, 4
    addi $6, $0, 5
    addi $7, $0, 6

    # ALU and shift/mult coverage.
    add  $12, $3, $4      # 5
    sub  $13, $7, $2      # 5
    and  $14, $5, $6      # 4
    or   $15, $5, $6      # 5
    xor  $16, $5, $6      # 1
    sll  $17, $3, 3       # 16
    srl  $18, $17, 2      # 4
    mult $19, $4, $7      # 18

    # Immediate path coverage.
    lui  $20, 0x1234
    ori  $20, $20, 0x5678 # 0x12345678
    addi $21, $2, 15      # 16

    # Load/store coverage on translated data addresses.
    la   $22, src0
    lw   $23, 0($22)      # 0x11
    la   $24, scratch
    sw   $23, 0($24)
    lw   $25, 0($24)      # 0x11
    lw   $26, 4($22)      # 0x22
    sw   $26, 4($24)
    lw   $27, 4($24)      # 0x22

    # AES instruction coverage.
    # aesenc stores encrypted block word in rd and full block internally.
    # aesdec decrypts internal block and returns first plaintext word.
    aesenc $10, $6, $7
    aesdec $11            # expected: 5

    # Align control-flow section to a block boundary (4 instructions).
    nop
    nop
    nop

    # beq not taken coverage.
    addi $28, $0, 7
    beq  $2, $3, beq_fail
    addi $28, $28, 1      # 8
    nop

    # beq taken coverage (target on block start).
    addi $29, $0, 9
    beq  $2, $2, beq_taken_ok
    addi $29, $0, 0xEE
    nop

beq_taken_ok:
    # bne not taken coverage.
    addi $29, $29, 1      # 10
    addi $30, $0, 11
    bne  $4, $4, bne_fail_not
    addi $30, $30, 1      # 12

    # bne taken coverage (target on block start).
    addi $31, $0, 13
    bne  $2, $3, bne_taken_ok
    addi $31, $0, 0xEE
    nop

bne_taken_ok:
    # Jump coverage (target on block start).
    addi $31, $31, 1      # 14
    j    jump_ok
    addi $12, $0, 0       # must be skipped
    nop

jump_ok:
    nop
    nop
    nop
    nop

    # Signature mixes all tested paths.
    add  $8, $12, $13
    add  $8, $8, $14
    add  $8, $8, $15
    add  $8, $8, $16
    add  $8, $8, $17
    add  $8, $8, $18
    add  $8, $8, $19
    add  $8, $8, $21
    add  $8, $8, $25
    add  $8, $8, $27
    add  $8, $8, $28
    add  $8, $8, $29
    add  $8, $8, $30
    add  $8, $8, $31
    add  $8, $8, $11      # final expected signature: 0xAE

    la $9, signature
    sw $8, 0($9)

    j end
    nop

beq_fail:
bne_fail_not:
    # Any unexpected branch path writes a failure signature.
    addi $8, $0, 0xDE
    la   $9, signature
    sw   $8, 0($9)

end:
    j end
