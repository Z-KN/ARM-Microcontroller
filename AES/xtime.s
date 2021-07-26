    SECTION XTIME:CODE(1)
    PUBLIC xtime
xtime
        push {r1, r2}
        lsr r1, r0, #7      ;r1 result
        mov r2, #0x1b       ;r2 tmp
        mul r1, r1, r2
        eor r0, r1, r0, lsl #1
        pop {r1,r2}
    MOV pc,lr               ; Return.
    END
