; xor_file_encryption.asm
; Nexus-ARX Cipher Implementation
; A high-throughput custom ARX (Add-Rotate-XOR) Stream Cipher.
; Target: Linux x86-64

section .data
    msg_mode        db "Encrypt (E) or Decrypt (D)? ", 0
    msg_infile      db "Input file path: ", 0
    msg_outfile     db "Output file path: ", 0
    msg_key         db "Enter 32-byte encryption key (max 32 chars): ", 0
    msg_error       db "Error: Operation failed.", 10, 0
    newline         db 10, 0
    
    constants       db "Nexus-ARX-Cipher" ; 16 bytes of initialization constants

section .bss
    mode            resb 3
    infile_path     resb 256
    outfile_path    resb 256
    key_buffer      resb 33         ; 32 bytes of key material plus null terminator
    
    state           resd 16         ; 64 bytes (16 x 32-bit words), cipher internal state
    working_state   resd 16         ; 64 bytes, current pseudo-random keystream block
    
    fd_in           resq 1
    fd_out          resq 1
    
    buffer          resb 4096       ; I/O buffer
    bytes_read      resq 1
    char_tmp        resb 1

section .text
    global _start

%macro QUARTER_ROUND 4
    ; a = %1, b = %2, c = %3, d = %4
    ; A += B
    mov eax, [rdi + %1 * 4]
    add eax, [rdi + %2 * 4]
    mov [rdi + %1 * 4], eax
    
    ; D ^= A; D = ROL(D, 16)
    mov edx, [rdi + %4 * 4]
    xor edx, eax
    rol edx, 16
    mov [rdi + %4 * 4], edx
    
    ; C += D
    mov ecx, [rdi + %3 * 4]
    add ecx, edx
    mov [rdi + %3 * 4], ecx
    
    ; B ^= C; B = ROL(B, 12)
    mov ebx, [rdi + %2 * 4]
    xor ebx, ecx
    rol ebx, 12
    mov [rdi + %2 * 4], ebx
    
    ; A += B
    mov eax, [rdi + %1 * 4]
    add eax, ebx
    mov [rdi + %1 * 4], eax
    
    ; D ^= A; D = ROL(D, 8)
    mov edx, [rdi + %4 * 4]
    xor edx, eax
    rol edx, 8
    mov [rdi + %4 * 4], edx
    
    ; C += D
    mov ecx, [rdi + %3 * 4]
    add ecx, edx
    mov [rdi + %3 * 4], ecx
    
    ; B ^= C; B = ROL(B, 7)
    mov ebx, [rdi + %2 * 4]
    xor ebx, ecx
    rol ebx, 7
    mov [rdi + %2 * 4], ebx
%endmacro

generate_keystream_block:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; rdi = working_state
    ; rsi = state
    
    ; Copy state into working_state
    mov rcx, 16
.copy_loop:
    mov eax, dword [rsi + rcx*4 - 4]
    mov dword [rdi + rcx*4 - 4], eax
    dec rcx
    jnz .copy_loop

    ; 10 iterations of double-rounds
    mov rcx, 10
.round_loop:
    push rcx
    ; Column rounds
    QUARTER_ROUND 0, 4, 8, 12
    QUARTER_ROUND 1, 5, 9, 13
    QUARTER_ROUND 2, 6, 10, 14
    QUARTER_ROUND 3, 7, 11, 15
    ; Diagonal rounds
    QUARTER_ROUND 0, 5, 10, 15
    QUARTER_ROUND 1, 6, 11, 12
    QUARTER_ROUND 2, 7, 8, 13
    QUARTER_ROUND 3, 4, 9, 14
    pop rcx
    dec rcx
    jnz .round_loop

    ; Add state to working_state to prevent reversibility
    mov rcx, 16
.add_loop:
    mov eax, dword [rsi + rcx*4 - 4]
    add dword [rdi + rcx*4 - 4], eax
    dec rcx
    jnz .add_loop

    ; Increment 64-bit block counter in state (words 12 and 13)
    add dword [rsi + 12*4], 1
    adc dword [rsi + 13*4], 0

    pop rdx
    pop rcx
    pop rbx
    pop rbp
    ret

_start:
    ; --- Prompt for Mode ---
    mov rdi, msg_mode
    call print_string
    mov rdi, mode
    mov rsi, 2
    call read_line

    mov al, byte [mode]
    cmp al, 'E'
    je .mode_ok
    cmp al, 'e'
    je .mode_ok
    cmp al, 'D'
    je .mode_ok
    cmp al, 'd'
    je .mode_ok
    jmp .error
.mode_ok:

    ; --- Prompt for Input File ---
    mov rdi, msg_infile
    call print_string
    mov rdi, infile_path
    mov rsi, 255
    call read_line

    ; --- Prompt for Output File ---
    mov rdi, msg_outfile
    call print_string
    mov rdi, outfile_path
    mov rsi, 255
    call read_line

    ; --- Prompt for Key ---
    mov rdi, msg_key
    call print_string
    mov rdi, key_buffer
    mov rsi, 32
    call read_line

    ; --- Initialize Nexus-ARX State ---
    ; 1. Copy 16-byte constant
    mov rcx, 16
    mov rsi, constants
    mov rdi, state
    rep movsb

    ; 2. Copy 32-byte key
    mov rcx, 32
    mov rsi, key_buffer
    mov rdi, state + 16
    rep movsb

    ; 3. Explicitly initialize counter & nonce to 0
    mov rcx, 16
    xor al, al
    mov rdi, state + 48
    rep stosb

    ; --- Open Input File ---
    mov rax, 2              ; sys_open
    mov rdi, infile_path
    mov rsi, 0              ; O_RDONLY
    mov rdx, 0
    syscall
    cmp rax, 0
    jl .error
    mov [fd_in], rax

    ; --- Open Output File ---
    mov rax, 2              ; sys_open
    mov rdi, outfile_path
    mov rsi, 577            ; O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0o644
    syscall
    cmp rax, 0
    jl .error
    mov [fd_out], rax

    ; --- Streaming Loop ---
.process_loop:
    mov rax, 0              ; sys_read
    mov rdi, [fd_in]
    mov rsi, buffer
    mov rdx, 4096
    syscall

    cmp rax, 0
    je .done                ; EOF
    jl .error               ; Read error

    mov [bytes_read], rax
    xor r13, r13            ; r13 = chunk offset in buffer

.chunk_loop:
    cmp r13, [bytes_read]
    jge .write_block

    ; Generate 64-byte keystream block
    mov rdi, working_state
    mov rsi, state
    call generate_keystream_block

    ; XOR up to 64 bytes
    xor r14, r14            ; r14 = byte index in chunk (0-63)
.xor_loop:
    cmp r14, 64
    jge .chunk_done
    
    mov r15, r13
    add r15, r14
    cmp r15, [bytes_read]
    jge .chunk_done         ; EOF reached within chunk

    mov al, byte [buffer + r15]
    mov bl, byte [working_state + r14]
    xor al, bl
    mov byte [buffer + r15], al

    inc r14
    jmp .xor_loop

.chunk_done:
    add r13, 64
    jmp .chunk_loop

.write_block:
    mov rax, 1              ; sys_write
    mov rdi, [fd_out]
    mov rsi, buffer
    mov rdx, [bytes_read]
    syscall
    
    jmp .process_loop

.done:
    mov rax, 3
    mov rdi, [fd_in]
    syscall
    
    mov rax, 3
    mov rdi, [fd_out]
    syscall

    mov rax, 60
    mov rdi, 0
    syscall

.error:
    mov rdi, msg_error
    call print_string
    mov rax, 60
    mov rdi, 1
    syscall

; --- Helper Functions ---
print_string:
    push rax
    push rsi
    push rdx
    mov rsi, rdi
    xor rdx, rdx
.strlen:
    cmp byte [rsi + rdx], 0
    je .do_print
    inc rdx
    jmp .strlen
.do_print:
    mov rax, 1
    mov rdi, 1
    syscall
    pop rdx
    pop rsi
    pop rax
    ret

read_line:
    push rax
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi
    mov rcx, rsi
    xor rdx, rdx
.read_char:
    cmp rdx, rcx
    jge .finish

    mov rax, 0
    mov rdi, 0
    mov rsi, char_tmp
    push rdx
    push rcx
    mov rdx, 1
    syscall
    pop rcx
    pop rdx

    cmp rax, 0
    jle .finish

    mov al, byte [char_tmp]
    cmp al, 10
    je .finish

    mov byte [rbx + rdx], al
    inc rdx
    jmp .read_char
.finish:
    mov byte [rbx + rdx], 0
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
