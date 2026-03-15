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

PUBLIC TailCallImpl

TailCallImpl PROC
    ; Expects r10 = pointer to WorkItemContext
    ; WorkItemContext layout:
    ;   +000h  func ptr
    ;   +010h  argc (QWORD)
    ;   +018h  argv[0] -> rcx
    ;   +020h  argv[1] -> rdx
    ;   +028h  argv[2] -> r8
    ;   +030h  argv[3] -> r9

    mov r10, rdx            ; rdx = workItem
    mov rax, [r10]          ; rax = workItem.func

    mov r11, [r10 + 010h]   ; r11 = argc

    cmp r11, 4
    jg tc_skip              ; only supports up to 4 args

    cmp r11, 0
    jle tc_call             ; no args

    mov rcx, [r10 + 018h]   ; argv[0]
    cmp r11, 1
    jle tc_call

    mov rdx, [r10 + 020h]   ; argv[1]
    cmp r11, 2
    jle tc_call

    mov r8,  [r10 + 028h]   ; argv[2]
    cmp r11, 3
    jle tc_call

    mov r9,  [r10 + 030h]   ; argv[3]

tc_call:
    jmp rax

tc_skip:
    xor eax, eax
    ret

TailCallImpl ENDP

END