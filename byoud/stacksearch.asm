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

; RCX - QWORD value to search for
; Returns:
;   RAX = offset in bytes from RSP to found address, or 0 if not found

StackSearch PROC
    mov r11, rsp             ; Save current RSP
    mov r10, gs:[08h]        ; Get StackBase from TEB

    mov r8, r11              ; R8 = search pointer (start from RSP)

search_loop:
    cmp r8, r10             ; Have we reached StackBase?
    jae not_found            ; If yes, stop

    cmp qword ptr [r8], rcx ; Compare memory at [RDX] with search value
    je found

    add r8, 8               ; Move to next QWORD
    jmp search_loop

found:
    mov rax, r8
    mov [rdx], r8            ; RDX = pointer to var that stores btit
    sub rax, r11             ; RAX = found address - RSP
    ret

not_found:
    xor rax, rax
    ret

StackSearch ENDP

END
