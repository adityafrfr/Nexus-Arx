# Nexus-ARX / Nexus-ARX-T

Educational file-encryption prototypes that combine an x86-64 Assembly ARX keystream core with a C driver and a lightweight GUI. The repository includes both the newer Nexus-ARX-T implementation and an older standalone XOR/ARX prototype for historical context.

Security note: this repository is for coursework and research. It is not a production-ready cryptosystem and has not been audited.

## Repository Map

Core code:
- `nexus_arx_t.c` - main C driver and CLI (v2 default, v3/v4 experimental)
- `nexus_arx_core.asm` - ARX keystream core used by the driver
- `gui.c` - GUI wrapper for the CLI (GTK on Linux, Win32 on Windows)
- `xor_file_encryption.asm` - legacy, standalone XOR/ARX prototype

Scripts:
- `build_gui.sh` - build backend + GUI
- `script.sh` - build + launch GUI
- `verify.sh` - functional verification checks
- `benchmark.sh` - throughput benchmarks

Documentation:
- `research_paper.md`
- `nexus_arx_architecture.md`
- `Paper final/` (paper drafts and templates)
- `synopsis.*`, `paper.odt`, and related notes

Benchmarks:
- `bench_*` fixtures in the repo root
- `benchmark_artifacts/` (benchmark outputs and results)

## Build (Linux)

Dependencies:
- `nasm`, `gcc`, `pkg-config`
- OpenSSL development headers
- GTK3 development headers (GUI only)

Build backend + GUI:

```bash
bash build_gui.sh
```

Build backend only:

```bash
nasm -f elf64 nexus_arx_core.asm -o nexus_arx_core.o
gcc -O3 -DNDEBUG -c nexus_arx_t.c -o nexus_arx_t.o $(pkg-config --cflags openssl)
gcc -O3 nexus_arx_t.o nexus_arx_core.o -o nexus_arx_t $(pkg-config --libs openssl)
```

## Run (CLI and GUI)

CLI (password via env):

```bash
env NEXUS_ARX_PASSWORD="your-password" ./nexus_arx_t E input.bin output.enc
env NEXUS_ARX_PASSWORD="your-password" ./nexus_arx_t D output.enc output.bin
```

Experimental modes:

```bash
env NEXUS_ARX_PASSWORD="your-password" ./nexus_arx_t E input.bin output.enc --experimental
env NEXUS_ARX_PASSWORD="your-password" ./nexus_arx_t E input.bin output.enc --experimental-v3
```

Deterministic test-vector mode:

```bash
env NEXUS_ARX_DETERMINISTIC=1 NEXUS_ARX_PASSWORD="your-password" ./nexus_arx_t E input.bin output.enc
```

GUI (Linux build):

```bash
./xor_gui_linux
```

## End-to-End Flow (Nexus-ARX-T)

At a high level, the current implementation follows this pipeline:

1. Acquire the password from the environment, stdin, or a hidden prompt.
2. Build a fixed-size header (78 bytes) that stores metadata, salt, nonce, and tag space.
3. Derive keys from the password and salt (scrypt for v2/v3/v4; PBKDF2 for v1).
4. Encrypt or decrypt in streaming chunks (4 KB for v2, 64 KB for v3/v4).
5. Authenticate (AEAD tag for v2; HMAC-SHA256 for v3/v4) and rewrite/verify the header.
6. During decryption, write to a temporary file and only commit on auth success.

The CLI auto-dispatches decryption based on the header version, so a single `D` operation can handle v2, v4, v3, or legacy v1 files.

## File Format (Nexus-ARX-T)

All modes use the same packed header layout. The header is 78 bytes and the `hmac_tag` field is interpreted differently depending on the version.

```c
typedef struct __attribute__((packed)) {
	uint8_t magic[8];               /* "NXARXT01"                          */
	uint8_t version;                /* format version                       */
	uint8_t flags;                  /* bit0: deterministic test-vector mode */
	uint8_t chunk_size_le[4];       /* chunk size used for this file         */
	uint8_t original_size_le[8];    /* original plaintext size               */
	uint8_t salt[SALT_LEN];         /* KDF salt                              */
	uint8_t nonce[NONCE_LEN];       /* per-file nonce                        */
	uint8_t hmac_tag[HMAC_TAG_LEN]; /* v2: AEAD tag (first 16 bytes), v1/v3/v4: HMAC */
} FileHeader;

#define HEADER_AAD_LEN ((int)offsetof(FileHeader, hmac_tag))
```

Header fields:

| Field | Size | Notes |
| --- | --- | --- |
| `magic` | 8 | ASCII `NXARXT01` |
| `version` | 1 | 1, 2, 3, or 4 |
| `flags` | 1 | bit0 = deterministic test-vector mode |
| `chunk_size_le` | 4 | 4096 (v2), 65536 (v3/v4) |
| `original_size_le` | 8 | plaintext byte length |
| `salt` | 16 | password KDF salt |
| `nonce` | 8 | per-file nonce |
| `hmac_tag` | 32 | v2 uses first 16 bytes for AEAD tag |

## Password Handling

Password sources are evaluated in order: `NEXUS_ARX_PASSWORD`, then `--pass-stdin`, then a hidden TTY prompt. This avoids putting the password in argv.

```c
static int acquire_password(int pass_from_stdin, char out[PASSWORD_MAX_LEN]) {
	const char *env_pw = getenv(PASSWORD_ENV);
	if (env_pw != NULL && env_pw[0] != '\0') {
		return copy_password_string(out, env_pw);
	}

	if (pass_from_stdin) {
		return read_password_from_stdin(out);
	}

	return prompt_hidden_password(out);
}
```

The GUI enforces a 1-128 character password length. The CLI allows longer passwords (up to `PASSWORD_MAX_LEN`).

## Key Derivation

The code uses different KDFs per profile:

- v1 (legacy, decrypt-only): PBKDF2-HMAC-SHA256, 100000 iterations.
- v2 (default): scrypt with `N=32768`, `r=8`, `p=1`, `maxmem=64 MiB`.
- v3/v4 (experimental): scrypt, 64-byte output split into encryption and HMAC keys.

Example from the scrypt path:

```c
if (EVP_PBE_scrypt(password,
				   strlen(password),
				   salt,
				   SALT_LEN,
				   SCRYPT_N,
				   SCRYPT_R,
				   SCRYPT_P,
				   SCRYPT_MAXMEM,
				   key,
				   KEY_LEN) != 1) {
	return 0;
}
```

## Mode Profiles and Working Details

### v2 (default) - scrypt + ChaCha20-Poly1305

This is the standard mode for new encryptions. It uses an AEAD construction and binds the header prefix as additional authenticated data (AAD).

Key steps:

1. Build the header with random salt and nonce (or deterministic values if enabled).
2. Derive a 32-byte key via scrypt.
3. Initialize ChaCha20-Poly1305 with a 12-byte IV built from the 8-byte nonce.
4. Bind the header prefix as AAD, then stream encrypt the file.
5. Finalize the AEAD tag and rewrite the header with the tag.

Code path (AEAD init and header binding):

```c
if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_IV_LEN, NULL) != 1 ||
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
	fprintf(stderr, "Error: AEAD initialization failed.\n");
	goto cleanup;
}

{
	int aad_len = 0;
	if (EVP_EncryptUpdate(ctx, NULL, &aad_len, (const uint8_t *)&hdr, HEADER_AAD_LEN) != 1) {
		fprintf(stderr, "Error: AEAD header binding failed.\n");
		goto cleanup;
	}
}
```

Decryption writes to a temporary file and commits only if authentication succeeds:

```c
snprintf(tmp_path, need, "%s.tmp.%ld", outpath, (long)getpid());
...
if (EVP_DecryptFinal_ex(ctx, outbuf, &final_len) != 1) {
	fprintf(stderr, "Error: authentication failed (wrong password or tampered file).\n");
	goto cleanup;
}
...
if (rename(tmp_path, outpath) != 0) {
	fprintf(stderr, "Error: failed to finalize output file: %s\n", strerror(errno));
	goto cleanup;
}
```

### v3 (experimental) - custom ARX + HMAC (scrypt)

v3 uses the custom ARX core for keystream generation and HMAC-SHA256 for authentication. It uses 64 KB chunks and rekeys state based on ciphertext feedback.

Core per-chunk flow:

```c
nexus_arx_inject_tweak(state, chunk_index, file_nonce_lo, original_size, domain);

while (processed < n) {
	size_t take = n - processed;
	if (take > BLOCK_SIZE) {
		take = BLOCK_SIZE;
	}
	nexus_arx_generate_block(working, state);
	xor_bytes(buf + processed, (const uint8_t *)working, take);
	processed += take;
}

if (!hmac_stream_update(&hmac, buf, n)) {
	fprintf(stderr, "Error: HMAC update failed.\n");
	goto cleanup;
}

{
	uint32_t feedback[4];
	extract_feedback(buf, n, feedback);
	nexus_arx_rekey(state, feedback);
	nexus_arx_wipe(feedback, sizeof(feedback));
}
```

The header tag is the final HMAC over `header || ciphertext` (with the tag field initially zeroed during verification).

### v4 (experimental) - trajectory-coupled ARX + HMAC (scrypt)

v4 extends v3 with a SHA-256 ratchet that influences per-chunk tweaks and applies a dual rekey per chunk. It also uses 64 KB chunks.

Ratchet-driven tweak and dual rekey (shown from decrypt path, same logic applies in encrypt):

```c
uint32_t domain_i = domain ^ load_u32_le(ratchet);
uint64_t nonce_mix = file_nonce_lo ^ load_u64_le(ratchet + 8);
uint64_t size_mix = original_size ^ load_u64_le(ratchet + 16);

nexus_arx_inject_tweak(state, chunk_index, nonce_mix, size_mix, domain_i);

memcpy(rat_words1, ratchet, 16);
memcpy(rat_words2, ratchet + 16, 16);
for (int i = 0; i < 4; i++) {
	rekey1[i] = feedback[i] ^ rat_words1[i];
	rekey2[i] = feedback[i] + rat_words2[i];
}
nexus_arx_rekey(state, rekey1);
nexus_arx_rekey(state, rekey2);
```

### v1 (legacy, decrypt-only)

v1 exists for compatibility with earlier outputs. It uses PBKDF2-HMAC-SHA256 and the ARX core, but it is not the default for new encryptions.

## Assembly Core Details (nexus_arx_core.asm)

The ARX core maintains a 512-bit internal state of sixteen 32-bit words. It exports functions to initialize the state, generate keystream blocks, inject per-chunk tweaks, rekey from feedback, and wipe buffers.

State layout (conceptual):

| Word range | Contents |
| --- | --- |
| 0-3 | 16-byte constant string "Nexus-ARX-Cipher" |
| 4-11 | 32-byte encryption key |
| 12-13 | 64-bit block counter |
| 14-15 | 64-bit nonce |

Quarter-round (ARX) macro:

```asm
%macro QUARTER_ROUND 4
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
%endmacro
```

The `nexus_arx_generate_block` routine copies the state, runs 10 double-rounds (20 total), adds the original state back, and increments the 64-bit counter.

Tweak and rekey operations are implemented directly in assembly. Example from the tweak injection:

```asm
xor  dword [rdi + 14*4], esi   ; state[14] ^= low32(chunk_index)
xor  dword [rdi + 15*4], edx   ; state[15] ^= low32(file_nonce_lo)
add  dword [rdi + 0*4], ecx    ; state[0]  += low32(file_size)
xor  dword [rdi + 1*4], r8d    ; state[1]  ^= domain
```

## Deterministic Test-Vector Mode

Setting `NEXUS_ARX_DETERMINISTIC=1` forces a fixed salt and nonce for reproducible output and sets the deterministic flag in the header.

```c
if (deterministic_mode_enabled()) {
	static const uint8_t fixed_salt[SALT_LEN] = { /* ... */ };
	static const uint8_t fixed_nonce[NONCE_LEN] = { /* ... */ };
	memcpy(salt, fixed_salt, SALT_LEN);
	memcpy(nonce, fixed_nonce, NONCE_LEN);
	*flags_io |= HEADER_FLAG_DETERMINISTIC;
	return 1;
}
```

## GUI Details (gui.c)

The GUI uses GTK on Linux and Win32 on Windows. It spawns the backend and supplies the password via `NEXUS_ARX_PASSWORD` (Windows) or `--pass-stdin` (Linux). Setting `NEXUS_ARX_GUI_EXPERIMENTAL=1` enables the experimental profile for encryption.

## Verification and Benchmarks

- `verify.sh` builds the backend and runs 13 functional checks, including wrong-password rejection, tamper detection, truncated-file rejection, and deterministic reproducibility.
- `benchmark.sh` measures throughput on 1 MB, 5 MB, and 20 MB inputs and records results in `benchmark_artifacts/benchmark_results.tsv`. If `openssl` is available, AES-256-CTR is benchmarked for comparison.

## Legacy XOR/ARX Prototype (xor_file_encryption.asm)

The legacy assembly-only tool performs direct XOR against an ARX-generated keystream with user-supplied key bytes and raw Linux syscalls. It has no authentication and no structured header, so it is included only for historical comparison.

Example snippet from the legacy keystream loop:

```asm
	; Generate 64-byte keystream block
	mov rdi, working_state
	mov rsi, state
	call generate_keystream_block

	; XOR up to 64 bytes
	; (loop continues...)
```

## Safety and Scope

- v2 uses a standard AEAD, but the project as a whole is still a research prototype.
- v3 and v4 are experimental custom constructions that have not been formally analyzed.
- Use only for education, testing, or as a mini-project reference, not for real data protection.
