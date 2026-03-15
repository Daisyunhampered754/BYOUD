; BYOUD
; Copyright (C) 2025-2026  Alessandro Magnosi (aka klezVirus)

; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.

; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.

; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>.
;

.code

PUBLIC CallGate

; RCX = pointer to CALLGATE_PARAMS structure
CallGate PROC
    ; int 3 ; breakpoint for debugging - remove in production
    ; Save non-volatile registers we'll use
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; Save params pointer in non-volatile register
    mov r12, rcx
    
    ; Load structure fields
    mov r13, [r12]          ; r13 = pFunction
    mov r14, [r12 + 08h]    ; r14 = dwMinimumFrameSize
    mov r15, [r12 + 10h]    ; r15 = argc
    lea rbp, [r12 + 18h]    ; rbp = &argv[0]


    ; Allocate stack frame
    sub rsp, r14
    
    ; Check argc
    cmp r15, 0
    jle do_call
    
    ; Load rcx (arg 0)
    mov rcx, [rbp]
    cmp r15, 1
    jle do_call
    
    ; Load rdx (arg 1)
    mov rdx, [rbp + 08h]
    cmp r15, 2
    jle do_call
    
    ; Load r8 (arg 2)
    mov r8, [rbp + 10h]
    cmp r15, 3
    jle do_call
    
    ; Load r9 (arg 3)
    mov r9, [rbp + 18h]
    cmp r15, 4
    jle do_call
    
    ; Handle stack-based parameters (5+)
    mov rbx, rcx            ; backup rcx
    lea rsi, [rbp + 20h]    ; source = &argv[4]
    lea rdi, [rsp + 28h]    ; dest = rsp + shadow space + return addr
    mov rcx, r15
    sub rcx, 4              ; count = argc - 4
    rep movsq
    mov rcx, rbx            ; restore rcx
    
do_call:
    ; Call the function
    test r13, r13
    jz skip
    call r13
    
skip:
    ; Deallocate stack frame
    add rsp, r14
    
    ; Restore non-volatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    
    ret
CallGate ENDP
END