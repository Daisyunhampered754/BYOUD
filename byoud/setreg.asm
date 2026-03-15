.code

PUBLIC GetRSP

SetRSI PROC
    mov rsi, rcx
    ret
SetRSI ENDP

GetRSP PROC
    mov rax, rsp
    ret
GetRSP ENDP


END

