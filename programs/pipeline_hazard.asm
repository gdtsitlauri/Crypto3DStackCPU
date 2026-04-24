.data
signature: .word 0x00000000
values:    .word 0x0000000A, 0x00000014, 0x00000000, 0x00000000
scratch:   .space 16

.text
.globl main
main:
    # ALU-to-ALU forwarding: $2 is consumed immediately by addi $3.
    addi $2, $0, 5
    addi $3, $2, 7       # 12, requires EX/MEM forwarding
    add  $4, $3, $2      # 17, requires chained forwarding

    # Load-use hazard: add $7 consumes $6 immediately after lw.
    la   $5, values
    lw   $6, 0($5)       # 10
    add  $7, $6, $4      # 27, requires one load-use stall then forwarding

    # Store-data forwarding: sw consumes the just-produced $7 value.
    sw   $7, 8($5)
    lw   $8, 8($5)       # 27
    add  $9, $8, $7      # 54, load-use + ALU forwarding mix

    # Write functional signature.
    la   $10, signature
    sw   $9, 0($10)

    # Align terminal loop target to a 4-instruction block boundary.
    nop
    nop
    nop

end:
    j end
    nop
    nop
    nop
