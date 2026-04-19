; nexus_arx_core.asm
; Nexus-ARX-T Cipher Core — callable from C via System V AMD64 ABI
; Exports:
;   void nexus_arx_generate_block(uint32_t working_state[16], const uint32_t state[16]);
;   void nexus_arx_init_state(uint32_t state[16],
;                             const uint8_t constants[16],
;                             const uint8_t key[32],
;                             const uint8_t nonce_counter[16]);
;   void nexus_arx_inject_tweak(uint32_t state[16],
;                                uint64_t chunk_index,
;                                uint64_t file_nonce_lo,
;                                uint64_t file_size,
;                                uint32_t domain);
;   void nexus_arx_rekey(uint32_t state[16], const uint32_t feedback[4]);
;   void nexus_arx_wipe(void *buf, uint64_t len);

section .text

global nexus_arx_generate_block
global nexus_arx_init_state
global nexus_arx_inject_tweak
global nexus_arx_rekey
global nexus_arx_wipe

; ============================================================
; QUARTER_ROUND macro — Add, Rotate, XOR on four 32-bit words
; rdi points to the state array throughout
; ============================================================
%macro QUARTER_ROUND 4
    ; %1=a, %2=b, %3=c, %4=d (indices into uint32_t array)
    mov eax, [rdi + %1 * 4]
    add eax, [rdi + %2 * 4]
    mov [rdi + %1 * 4], eax

    mov edx, [rdi + %4 * 4]
    xor edx, eax
    rol edx, 16
    mov [rdi + %4 * 4], edx

    mov ecx, [rdi + %3 * 4]
    add ecx, edx
    mov [rdi + %3 * 4], ecx

    mov ebx, [rdi + %2 * 4]
    xor ebx, ecx
    rol ebx, 12
    mov [rdi + %2 * 4], ebx

    mov eax, [rdi + %1 * 4]
    add eax, ebx
    mov [rdi + %1 * 4], eax

    mov edx, [rdi + %4 * 4]
    xor edx, eax
    rol edx, 8
    mov [rdi + %4 * 4], edx

    mov ecx, [rdi + %3 * 4]
    add ecx, edx
    mov [rdi + %3 * 4], ecx

    mov ebx, [rdi + %2 * 4]
    xor ebx, ecx
    rol ebx, 7
    mov [rdi + %2 * 4], ebx
%endmacro

; ============================================================
; nexus_arx_generate_block(uint32_t working[16], const uint32_t state[16])
;   rdi = working_state (output)
;   rsi = state (input, read-only)
;
;   1. Copy state -> working_state
;   2. Run 10 double-rounds (20 total rounds)
;   3. Add original state back into working_state
;   4. Increment 64-bit block counter in state[12..13]
; ============================================================
nexus_arx_generate_block:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13

    mov  r12, rdi          ; r12 = working_state
    mov  r13, rsi          ; r13 = state

    ; --- Copy state into working_state (16 x 32-bit words = 64 bytes) ---
    mov  rcx, 16
.copy:
    mov  eax, dword [r13 + rcx*4 - 4]
    mov  dword [r12 + rcx*4 - 4], eax
    dec  rcx
    jnz  .copy

    ; --- 10 double-rounds on working_state ---
    mov  r8d, 10           ; loop counter in r8d
.round_loop:
    mov  rdi, r12          ; rdi must point to working_state for QR macro

    ; Column rounds
    QUARTER_ROUND  0, 4,  8, 12
    QUARTER_ROUND  1, 5,  9, 13
    QUARTER_ROUND  2, 6, 10, 14
    QUARTER_ROUND  3, 7, 11, 15

    ; Diagonal rounds
    QUARTER_ROUND  0, 5, 10, 15
    QUARTER_ROUND  1, 6, 11, 12
    QUARTER_ROUND  2, 7,  8, 13
    QUARTER_ROUND  3, 4,  9, 14

    dec  r8d
    jnz  .round_loop

    ; --- Add original state to working_state ---
    mov  rcx, 16
.add_back:
    mov  eax, dword [r13 + rcx*4 - 4]
    add  dword [r12 + rcx*4 - 4], eax
    dec  rcx
    jnz  .add_back

    ; --- Increment 64-bit block counter: state[12] (low), state[13] (high) ---
    add  dword [r13 + 12*4], 1
    adc  dword [r13 + 13*4], 0

    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================
; nexus_arx_init_state(uint32_t state[16],
;                      const uint8_t constants[16],
;                      const uint8_t key[32],
;                      const uint8_t nonce_counter[16])
;   rdi = state
;   rsi = constants (16 bytes)
;   rdx = key (32 bytes)
;   rcx = nonce_counter (16 bytes: 8 counter + 8 nonce)
; ============================================================
nexus_arx_init_state:
    push rbp
    mov  rbp, rsp

    ; Copy 16 bytes of constants into state[0..3]
    mov  rax, [rsi]
    mov  [rdi], rax
    mov  rax, [rsi + 8]
    mov  [rdi + 8], rax

    ; Copy 32 bytes of key into state[4..11]
    mov  rax, [rdx]
    mov  [rdi + 16], rax
    mov  rax, [rdx + 8]
    mov  [rdi + 24], rax
    mov  rax, [rdx + 16]
    mov  [rdi + 32], rax
    mov  rax, [rdx + 24]
    mov  [rdi + 40], rax

    ; Copy 16 bytes of nonce_counter into state[12..15]
    mov  rax, [rcx]
    mov  [rdi + 48], rax
    mov  rax, [rcx + 8]
    mov  [rdi + 56], rax

    pop  rbp
    ret

; ============================================================
; nexus_arx_inject_tweak(uint32_t state[16],
;                        uint64_t chunk_index,     ; rsi
;                        uint64_t file_nonce_lo,   ; rdx
;                        uint64_t file_size,       ; rcx
;                        uint32_t domain)          ; r8d
;
; Per-chunk tweak injection:
;   state[14] ^= low32(chunk_index)
;   state[15] ^= low32(file_nonce_lo)
;   state[0]  += low32(file_size)
;   state[1]  ^= domain
;   state[2]   = ROL(state[2] ^ high32(chunk_index), 5)
;
; This keeps the tweak file-aware and chunk-aware while preserving
; the ARX style.
; ============================================================
nexus_arx_inject_tweak:
    push rbp
    mov  rbp, rsp

    ; state[14] ^= low32(chunk_index)
    xor  dword [rdi + 14*4], esi

    ; state[15] ^= low32(file_nonce_lo)
    xor  dword [rdi + 15*4], edx

    ; state[0] += low32(file_size)
    add  dword [rdi + 0*4], ecx

    ; state[1] ^= domain
    xor  dword [rdi + 1*4], r8d

    ; state[2] = ROL(state[2] ^ high32(chunk_index), 5)
    mov  eax, dword [rdi + 2*4]
    mov  r9, rsi
    shr  r9, 32
    xor  eax, r9d
    rol  eax, 5
    mov  dword [rdi + 2*4], eax

    pop  rbp
    ret

; ============================================================
; nexus_arx_rekey(uint32_t state[16], const uint32_t feedback[4])
;
; Self-rekeying: fold 4 feedback words back into key area of state.
;   state[4] += feedback[0]   (with rotation for diffusion)
;   state[5] ^= feedback[1]
;   state[6] += feedback[2]
;   state[7] ^= feedback[3]
;
;   rdi = state
;   rsi = feedback (4 x uint32_t)
; ============================================================
nexus_arx_rekey:
    push rbp
    mov  rbp, rsp

    ; state[4] = ROL(state[4] + feedback[0], 7)
    mov  eax, [rsi]
    add  eax, [rdi + 4*4]
    rol  eax, 7
    mov  [rdi + 4*4], eax

    ; state[5] ^= feedback[1]
    mov  eax, [rsi + 4]
    xor  [rdi + 5*4], eax

    ; state[6] = ROL(state[6] + feedback[2], 13)
    mov  eax, [rsi + 8]
    add  eax, [rdi + 6*4]
    rol  eax, 13
    mov  [rdi + 6*4], eax

    ; state[7] ^= feedback[3]
    mov  eax, [rsi + 12]
    xor  [rdi + 7*4], eax

    pop  rbp
    ret

; ============================================================
; nexus_arx_wipe(void *buf, uint64_t len)
;   Overwrites memory with zeroes.  Used for key/state cleanup.
;   rdi = buffer
;   rsi = length
; ============================================================
nexus_arx_wipe:
    push rbp
    mov  rbp, rsp
    mov  rcx, rsi
    xor  al, al
    rep  stosb
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
