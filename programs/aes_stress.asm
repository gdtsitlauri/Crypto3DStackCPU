.data
signature: .word 0x00000000
scratch:   .space 16

.text
.globl main
main:
    # AES ISA stress: two aesenc/aesdec round trips using the sealed image key.
    addi   $2, $0, 5
    addi   $3, $0, 9
    aesenc $4, $2, $3
    aesdec $5              # first decrypted word returns 5
    aesenc $6, $5, $3
    aesdec $7              # first decrypted word returns 5
    add    $8, $5, $7      # 10
    la     $9, signature
    sw     $8, 0($9)
    nop
    nop

end:
    j end
    nop
    nop
    nop
