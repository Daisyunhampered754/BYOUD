.data

gFunctionPointer QWORD 0
gMinimumFrameSize QWORD 0
gRCX QWORD 0
gRSI QWORD 0
gRDI QWORD 0
gAllocation QWORD 0

.code

PUBLIC RailGun

RailGun PROC
  mov gRSI, rsi
  mov gRDI, rdi
  
  ; RCX fPtr
  MOV gFunctionPointer, RCX
  MOV gMinimumFrameSize, r9
  
  ; .allocstack <R9>
  sub rsp, r9
  ; .endprolog

  ; Moving RDX and R8 to R10 and R11 to avoid clobbering
  mov r11, rdx
  mov r10, r8

  cmp r11, 0
  jle do_call              ; no args, just call
    
  mov rcx, [r10]
  cmp r11, 1
  jle do_call
  
  mov rdx, [r10 + 08h]
  cmp r11, 2
  jle do_call

  mov r8, [r10 + 010h]
  cmp r11, 3
  jle do_call

  mov r9, [r10 + 018h]
  cmp r11, 4
  jle do_call
  
  ; backup rcx
  mov gRCX, rcx

  ; other parameters
  lea rsi, [r10 + 020h]
  lea rdi, [rsp + 038h]

  ; setting rcx as conter Argc - 4 (reg based params)
  mov rcx, r11
  sub rcx, 04h

  ; move stack based params all at once
  rep movsq

  ; Retore rcx
  mov rcx, gRCX

do_call:
  mov rax, gFunctionPointer
  test rax, rax
  jz skip
  call rax

skip:
  mov r9, gMinimumFrameSize
  add rsp, r9
  mov rsi, gRSI
  mov rdi, gRDI
  ret

RailGun ENDP

END