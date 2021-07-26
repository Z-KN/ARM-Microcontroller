    SECTION MULTIPLY:CODE(2)
    PUBLIC Multiply
    IMPORT xtime
Multiply
        push {lr}           ;r0 = x                            
        ubfx r3, r1, #0, #1 ;r1 = y
        mul r2, r3, r0      ;r2 = result
        bl xtime
        uxtb r0,r0
        ubfx r3, r1, #1, #1
        mul r3, r0, r3
        eor r2, r2, r3
        bl xtime
        uxtb r0,r0
        ubfx r3, r1, #2, #1
        mul r3, r3, r0
        eor r2, r2, r3
        bl xtime
        uxtb r0,r0
        ubfx r3, r1, #3, #1
        mul r3, r3, r0
        eor r2, r2, r3     
        mov r0, r2
        uxtb r0,r0
        pop {lr}
        MOV pc,lr           ; Return.
        END
