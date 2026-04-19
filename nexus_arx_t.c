/*
 * nexus_arx_t.c — Nexus-ARX-T File Encryption Driver
 *
 * Format versions:
 * - v1: Legacy custom ARX stream + HMAC-SHA256 (decrypt-only for compatibility)
 * - v2: ChaCha20-Poly1305 + scrypt (default for new encryptions)
 *
 * Security changes in v2:
 * - password is no longer passed as a CLI argument
 * - stronger KDF (scrypt)
 * - authenticated encryption (AEAD)
 * - single-pass decrypt to temporary file, commit-on-auth-success
 */

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

/* ---------- Assembly-provided functions (used for v1 compatibility) ---------- */
extern void nexus_arx_generate_block(uint32_t working[16],
                                     const uint32_t state[16]);
extern void nexus_arx_init_state(uint32_t state[16],
                                 const uint8_t constants[16],
                                 const uint8_t key[32],
                                 const uint8_t nonce_counter[16]);
extern void nexus_arx_inject_tweak(uint32_t state[16],
                                   uint64_t chunk_index,
                                   uint64_t file_nonce_lo,
                                   uint64_t file_size,
                                   uint32_t domain);
extern void nexus_arx_rekey(uint32_t state[16],
                            const uint32_t feedback[4]);
extern void nexus_arx_wipe(void *buf, uint64_t len);

/* ---------- Constants ---------- */
static const uint8_t NEXUS_MAGIC[8]    = {'N', 'X', 'A', 'R', 'X', 'T', '0', '1'};
static const uint8_t ARX_CONSTANTS[16] = "Nexus-ARX-Cipher";

#define HEADER_VERSION_V1 1u
#define HEADER_VERSION_V2 2u
#define HEADER_VERSION_V3 3u
#define HEADER_VERSION_V4 4u
#define HEADER_FLAG_DETERMINISTIC 0x01u

#define SALT_LEN        16u
#define NONCE_LEN        8u
#define KEY_LEN         32u
#define HMAC_KEY_LEN    32u
#define KDF_ITERATIONS 100000u
#define CHUNK_SIZE    4096u
#define CHUNK_SIZE_V3 65536u
#define CHUNK_SIZE_V4 65536u
#define BLOCK_SIZE      64u
#define HMAC_TAG_LEN    32u
#define AEAD_TAG_LEN    16u
#define AEAD_IV_LEN     12u

#define DETERMINISTIC_ENV "NEXUS_ARX_DETERMINISTIC"
#define PASSWORD_ENV "NEXUS_ARX_PASSWORD"
#define PASSWORD_MAX_LEN 1024u
#define DOMAIN_CONST 0x4E585431u /* "NXT1" */

/* scrypt parameters for v2 */
#define SCRYPT_N      32768u
#define SCRYPT_R          8u
#define SCRYPT_P          1u
#define SCRYPT_MAXMEM (64u * 1024u * 1024u)

/* ---------- File header (byte-oriented, portable on disk) ---------- */
typedef struct __attribute__((packed)) {
    uint8_t magic[8];               /* "NXARXT01"                         */
    uint8_t version;                /* format version                      */
    uint8_t flags;                  /* bit0: deterministic test-vector mode */
    uint8_t chunk_size_le[4];       /* chunk size used for this file       */
    uint8_t original_size_le[8];    /* original plaintext size             */
    uint8_t salt[SALT_LEN];         /* KDF salt                            */
    uint8_t nonce[NONCE_LEN];       /* per-file nonce (expanded to IV in v2) */
    uint8_t hmac_tag[HMAC_TAG_LEN]; /* v1: full HMAC tag, v2: first 16 bytes AEAD tag */
} FileHeader;

#define HEADER_AAD_LEN ((int)offsetof(FileHeader, hmac_tag))

typedef struct {
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;
} HmacStream;

/* ---------- Helpers ---------- */

static void store_u32_le(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
    out[2] = (uint8_t)((v >> 16) & 0xFFu);
    out[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t load_u32_le(const uint8_t in[4]) {
    return ((uint32_t)in[0]) |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

static void store_u64_le(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v & 0xFFu);
        v >>= 8;
    }
}

static uint64_t load_u64_le(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v <<= 8;
        v |= in[i];
    }
    return v;
}

static int str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int deterministic_mode_enabled(void) {
    const char *v = getenv(DETERMINISTIC_ENV);
    if (v == NULL) {
        return 0;
    }
    return str_ieq(v, "1") || str_ieq(v, "true") || str_ieq(v, "yes");
}

static int get_file_size(FILE *f, uint64_t *size_out) {
    if (fseek(f, 0, SEEK_END) != 0) {
        return 0;
    }
    long pos = ftell(f);
    if (pos < 0) {
        return 0;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        return 0;
    }
    *size_out = (uint64_t)pos;
    return 1;
}

static uint32_t compute_domain(uint8_t version, uint8_t flags, uint32_t chunk_size) {
    return DOMAIN_CONST ^
           ((uint32_t)version << 24) ^
           ((uint32_t)flags << 16) ^
           chunk_size;
}

static void trim_trailing_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static int copy_password_string(char out[PASSWORD_MAX_LEN], const char *src) {
    size_t len = strlen(src);
    if (len == 0 || len >= PASSWORD_MAX_LEN) {
        return 0;
    }
    memcpy(out, src, len + 1);
    return 1;
}

static int prompt_hidden_password(char out[PASSWORD_MAX_LEN]) {
    struct termios oldt;
    struct termios newt;

    if (!isatty(STDIN_FILENO)) {
        return 0;
    }
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        return 0;
    }

    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        return 0;
    }

    fprintf(stderr, "Password: ");
    fflush(stderr);

    if (fgets(out, (int)PASSWORD_MAX_LEN, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        fprintf(stderr, "\n");
        return 0;
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fprintf(stderr, "\n");

    trim_trailing_newline(out);
    return out[0] != '\0';
}

static int read_password_from_stdin(char out[PASSWORD_MAX_LEN]) {
    if (fgets(out, (int)PASSWORD_MAX_LEN, stdin) == NULL) {
        return 0;
    }
    trim_trailing_newline(out);
    return out[0] != '\0';
}

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

static int derive_keys_v1(const char *password, const uint8_t salt[SALT_LEN],
                          uint8_t enc_key[KEY_LEN], uint8_t hmac_key[HMAC_KEY_LEN]) {
    uint8_t derived[KEY_LEN + HMAC_KEY_LEN];
    int ok = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                               salt, SALT_LEN, KDF_ITERATIONS,
                               EVP_sha256(), KEY_LEN + HMAC_KEY_LEN, derived);
    if (ok != 1) {
        return 0;
    }
    memcpy(enc_key, derived, KEY_LEN);
    memcpy(hmac_key, derived + KEY_LEN, HMAC_KEY_LEN);
    nexus_arx_wipe(derived, sizeof(derived));
    return 1;
}

static int derive_key_v2(const char *password, const uint8_t salt[SALT_LEN],
                         uint8_t key[KEY_LEN]) {
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
    return 1;
}

static int derive_keys_v3(const char *password, const uint8_t salt[SALT_LEN],
                          uint8_t enc_key[KEY_LEN], uint8_t hmac_key[HMAC_KEY_LEN]) {
    uint8_t derived[KEY_LEN + HMAC_KEY_LEN];
    if (EVP_PBE_scrypt(password,
                       strlen(password),
                       salt,
                       SALT_LEN,
                       SCRYPT_N,
                       SCRYPT_R,
                       SCRYPT_P,
                       SCRYPT_MAXMEM,
                       derived,
                       sizeof(derived)) != 1) {
        return 0;
    }
    memcpy(enc_key, derived, KEY_LEN);
    memcpy(hmac_key, derived + KEY_LEN, HMAC_KEY_LEN);
    nexus_arx_wipe(derived, sizeof(derived));
    return 1;
}

static int fill_salt_nonce(uint8_t salt[SALT_LEN], uint8_t nonce[NONCE_LEN], uint8_t *flags_io) {
    if (deterministic_mode_enabled()) {
        static const uint8_t fixed_salt[SALT_LEN] = {
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
            0x11, 0x33, 0x55, 0x77, 0x99, 0xBB, 0xDD, 0xFF
        };
        static const uint8_t fixed_nonce[NONCE_LEN] = {
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28
        };
        memcpy(salt, fixed_salt, SALT_LEN);
        memcpy(nonce, fixed_nonce, NONCE_LEN);
        *flags_io |= HEADER_FLAG_DETERMINISTIC;
        return 1;
    }

    if (RAND_bytes(salt, SALT_LEN) != 1) {
        return 0;
    }
    if (RAND_bytes(nonce, NONCE_LEN) != 1) {
        return 0;
    }
    return 1;
}

static void build_v2_iv(uint8_t iv[AEAD_IV_LEN], const uint8_t nonce[NONCE_LEN]) {
    memset(iv, 0, AEAD_IV_LEN);
    memcpy(iv + (AEAD_IV_LEN - NONCE_LEN), nonce, NONCE_LEN);
}

static void xor_bytes(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

static void extract_feedback(const uint8_t *chunk, size_t chunk_len, uint32_t feedback[4]) {
    memset(feedback, 0, 16);
    if (chunk_len < 16) {
        memcpy(feedback, chunk, chunk_len);
        return;
    }
    size_t step = chunk_len / 4;
    for (int i = 0; i < 4; i++) {
        memcpy(&feedback[i], chunk + i * step, 4);
    }
}

static int hmac_stream_init(HmacStream *s, const uint8_t *key, size_t key_len) {
    char digest_name[] = "SHA256";
    OSSL_PARAM params[2];

    memset(s, 0, sizeof(*s));
    s->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (s->mac == NULL) {
        return 0;
    }
    s->ctx = EVP_MAC_CTX_new(s->mac);
    if (s->ctx == NULL) {
        EVP_MAC_free(s->mac);
        s->mac = NULL;
        return 0;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(s->ctx, key, key_len, params) != 1) {
        EVP_MAC_CTX_free(s->ctx);
        EVP_MAC_free(s->mac);
        s->ctx = NULL;
        s->mac = NULL;
        return 0;
    }
    return 1;
}

static int hmac_stream_update(HmacStream *s, const uint8_t *data, size_t len) {
    return EVP_MAC_update(s->ctx, data, len) == 1;
}

static int hmac_stream_final(HmacStream *s, uint8_t out[HMAC_TAG_LEN]) {
    size_t out_len = 0;
    if (EVP_MAC_final(s->ctx, out, &out_len, HMAC_TAG_LEN) != 1) {
        return 0;
    }
    return out_len == HMAC_TAG_LEN;
}

static void hmac_stream_cleanup(HmacStream *s) {
    if (s->ctx != NULL) {
        EVP_MAC_CTX_free(s->ctx);
        s->ctx = NULL;
    }
    if (s->mac != NULL) {
        EVP_MAC_free(s->mac);
        s->mac = NULL;
    }
}

static int sha256_bytes(const uint8_t *data, size_t len, uint8_t out[32]) {
    int ok = 0;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int out_len = 0;
    if (md == NULL) {
        return 0;
    }
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_DigestUpdate(md, data, len) != 1) {
        goto cleanup;
    }
    if (EVP_DigestFinal_ex(md, out, &out_len) != 1) {
        goto cleanup;
    }
    ok = (out_len == 32u);

cleanup:
    EVP_MD_CTX_free(md);
    return ok;
}

static int ratchet_seed(uint8_t ratchet[32], const FileHeader *hdr, uint64_t original_size, uint32_t domain) {
    uint8_t material[96];
    size_t p = 0;
    uint8_t tmp64[8];
    uint8_t tmp32[4];
    static const uint8_t label[] = "NXT4-RATCHET-SEED";

    memset(material, 0, sizeof(material));
    memcpy(material + p, hdr->salt, SALT_LEN);
    p += SALT_LEN;
    memcpy(material + p, hdr->nonce, NONCE_LEN);
    p += NONCE_LEN;
    store_u64_le(tmp64, original_size);
    memcpy(material + p, tmp64, sizeof(tmp64));
    p += sizeof(tmp64);
    store_u32_le(tmp32, domain);
    memcpy(material + p, tmp32, sizeof(tmp32));
    p += sizeof(tmp32);
    material[p++] = hdr->version;
    material[p++] = hdr->flags;
    memcpy(material + p, label, sizeof(label) - 1);
    p += sizeof(label) - 1;

    return sha256_bytes(material, p, ratchet);
}

static void sample_chunk_edges(const uint8_t *chunk, size_t chunk_len, uint8_t first16[16], uint8_t last16[16]) {
    memset(first16, 0, 16);
    memset(last16, 0, 16);
    if (chunk_len == 0) {
        return;
    }
    if (chunk_len < 16) {
        memcpy(first16, chunk, chunk_len);
        memcpy(last16, chunk, chunk_len);
        return;
    }
    memcpy(first16, chunk, 16);
    memcpy(last16, chunk + chunk_len - 16, 16);
}

static int ratchet_step(uint8_t ratchet[32],
                        uint64_t chunk_index,
                        uint32_t domain_i,
                        size_t chunk_len,
                        const uint8_t first16[16],
                        const uint8_t last16[16],
                        const uint32_t feedback[4]) {
    uint8_t material[96];
    size_t p = 0;
    uint8_t tmp64[8];
    uint8_t tmp32[4];
    uint8_t new_ratchet[32];

    memset(material, 0, sizeof(material));
    memcpy(material + p, ratchet, 32);
    p += 32;
    store_u64_le(tmp64, chunk_index);
    memcpy(material + p, tmp64, sizeof(tmp64));
    p += sizeof(tmp64);
    store_u32_le(tmp32, domain_i);
    memcpy(material + p, tmp32, sizeof(tmp32));
    p += sizeof(tmp32);
    store_u32_le(tmp32, (uint32_t)chunk_len);
    memcpy(material + p, tmp32, sizeof(tmp32));
    p += sizeof(tmp32);
    memcpy(material + p, first16, 16);
    p += 16;
    memcpy(material + p, last16, 16);
    p += 16;
    memcpy(material + p, feedback, 16);
    p += 16;

    if (!sha256_bytes(material, p, new_ratchet)) {
        return 0;
    }
    memcpy(ratchet, new_ratchet, 32);
    nexus_arx_wipe(new_ratchet, sizeof(new_ratchet));
    nexus_arx_wipe(material, sizeof(material));
    return 1;
}

/* ---------- Encrypt v2 (standard) ---------- */
static int do_encrypt_v2(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    FileHeader hdr;
    uint8_t key[KEY_LEN];
    uint8_t iv[AEAD_IV_LEN];
    uint8_t inbuf[CHUNK_SIZE];
    uint8_t outbuf[CHUNK_SIZE + AEAD_TAG_LEN];
    uint64_t original_size = 0;

    memset(&hdr, 0, sizeof(hdr));
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }
    fout = fopen(outpath, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open output file.\n");
        goto cleanup;
    }

    if (!get_file_size(fin, &original_size)) {
        fprintf(stderr, "Error: cannot determine input file size.\n");
        goto cleanup;
    }

    memcpy(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic));
    hdr.version = (uint8_t)HEADER_VERSION_V2;
    hdr.flags = 0;
    store_u32_le(hdr.chunk_size_le, CHUNK_SIZE);
    store_u64_le(hdr.original_size_le, original_size);

    if (!fill_salt_nonce(hdr.salt, hdr.nonce, &hdr.flags)) {
        fprintf(stderr, "Error: random generation failed.\n");
        goto cleanup;
    }

    if (!derive_key_v2(password, hdr.salt, key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }
    build_v2_iv(iv, hdr.nonce);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: cipher context allocation failed.\n");
        goto cleanup;
    }

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

    if (fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to write header.\n");
        goto cleanup;
    }

    while (1) {
        size_t n = fread(inbuf, 1, sizeof(inbuf), fin);
        int out_len = 0;

        if (n > 0) {
            if (EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, (int)n) != 1) {
                fprintf(stderr, "Error: encryption failed.\n");
                goto cleanup;
            }
            if (out_len > 0 && fwrite(outbuf, 1, (size_t)out_len, fout) != (size_t)out_len) {
                fprintf(stderr, "Error: failed to write ciphertext.\n");
                goto cleanup;
            }
        }

        if (n < sizeof(inbuf)) {
            if (ferror(fin)) {
                fprintf(stderr, "Error: read failure during encryption.\n");
                goto cleanup;
            }
            break;
        }
    }

    {
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &final_len) != 1) {
            fprintf(stderr, "Error: encryption finalize failed.\n");
            goto cleanup;
        }
        if (final_len > 0 && fwrite(outbuf, 1, (size_t)final_len, fout) != (size_t)final_len) {
            fprintf(stderr, "Error: failed to write final ciphertext block.\n");
            goto cleanup;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, hdr.hmac_tag) != 1) {
        fprintf(stderr, "Error: failed to get authentication tag.\n");
        goto cleanup;
    }

    if (fseek(fout, 0, SEEK_SET) != 0 || fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to finalize header.\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    nexus_arx_wipe(key, sizeof(key));
    nexus_arx_wipe(iv, sizeof(iv));
    nexus_arx_wipe(inbuf, sizeof(inbuf));
    nexus_arx_wipe(outbuf, sizeof(outbuf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (fin != NULL) {
        fclose(fin);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    return rc;
}

/* ---------- Encrypt v3 (experimental ARX mode) ---------- */
static int do_encrypt_v3(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    HmacStream hmac;
    int hmac_initialized = 0;

    FileHeader hdr;
    uint8_t enc_key[KEY_LEN];
    uint8_t hmac_key[HMAC_KEY_LEN];
    uint32_t state[16];
    uint32_t working[16];
    uint8_t nonce_counter[16];
    uint64_t original_size = 0;
    uint64_t file_nonce_lo = 0;
    uint32_t domain = 0;
    uint8_t buf[CHUNK_SIZE_V3];
    size_t n = 0;
    uint64_t chunk_index = 0;

    memset(&hdr, 0, sizeof(hdr));
    memset(enc_key, 0, sizeof(enc_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(state, 0, sizeof(state));
    memset(working, 0, sizeof(working));
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(buf, 0, sizeof(buf));
    memset(&hmac, 0, sizeof(hmac));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }
    fout = fopen(outpath, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open output file.\n");
        goto cleanup;
    }

    if (!get_file_size(fin, &original_size)) {
        fprintf(stderr, "Error: cannot determine input file size.\n");
        goto cleanup;
    }

    memcpy(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic));
    hdr.version = (uint8_t)HEADER_VERSION_V3;
    hdr.flags = 0;
    store_u32_le(hdr.chunk_size_le, CHUNK_SIZE_V3);
    store_u64_le(hdr.original_size_le, original_size);

    if (!fill_salt_nonce(hdr.salt, hdr.nonce, &hdr.flags)) {
        fprintf(stderr, "Error: random generation failed.\n");
        goto cleanup;
    }

    if (!derive_keys_v3(password, hdr.salt, enc_key, hmac_key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }

    memcpy(nonce_counter + 8, hdr.nonce, NONCE_LEN);
    nexus_arx_init_state(state, ARX_CONSTANTS, enc_key, nonce_counter);

    file_nonce_lo = load_u64_le(hdr.nonce);
    domain = compute_domain(hdr.version, hdr.flags, load_u32_le(hdr.chunk_size_le));

    if (fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to write header.\n");
        goto cleanup;
    }

    if (!hmac_stream_init(&hmac, hmac_key, HMAC_KEY_LEN)) {
        fprintf(stderr, "Error: HMAC init failed.\n");
        goto cleanup;
    }
    hmac_initialized = 1;

    if (!hmac_stream_update(&hmac, (const uint8_t *)&hdr, sizeof(hdr))) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t processed = 0;
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
        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "Error: failed to write ciphertext.\n");
            goto cleanup;
        }

        {
            uint32_t feedback[4];
            extract_feedback(buf, n, feedback);
            nexus_arx_rekey(state, feedback);
            nexus_arx_wipe(feedback, sizeof(feedback));
        }

        chunk_index++;
    }

    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during encryption.\n");
        goto cleanup;
    }

    if (!hmac_stream_final(&hmac, hdr.hmac_tag)) {
        fprintf(stderr, "Error: HMAC finalize failed.\n");
        goto cleanup;
    }

    if (fseek(fout, 0, SEEK_SET) != 0 || fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to finalize header.\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (hmac_initialized) {
        hmac_stream_cleanup(&hmac);
    }
    nexus_arx_wipe(enc_key, sizeof(enc_key));
    nexus_arx_wipe(hmac_key, sizeof(hmac_key));
    nexus_arx_wipe(state, sizeof(state));
    nexus_arx_wipe(working, sizeof(working));
    nexus_arx_wipe(nonce_counter, sizeof(nonce_counter));
    nexus_arx_wipe(buf, sizeof(buf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (fin != NULL) {
        fclose(fin);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    return rc;
}

/* ---------- Encrypt v4 (trajectory-coupled experimental ARX mode) ---------- */
static int do_encrypt_v4(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    HmacStream hmac;
    int hmac_initialized = 0;

    FileHeader hdr;
    uint8_t enc_key[KEY_LEN];
    uint8_t hmac_key[HMAC_KEY_LEN];
    uint8_t ratchet[32];
    uint32_t state[16];
    uint32_t working[16];
    uint8_t nonce_counter[16];
    uint64_t original_size = 0;
    uint64_t file_nonce_lo = 0;
    uint32_t domain = 0;
    uint8_t buf[CHUNK_SIZE_V4];
    size_t n = 0;
    uint64_t chunk_index = 0;

    memset(&hdr, 0, sizeof(hdr));
    memset(enc_key, 0, sizeof(enc_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(ratchet, 0, sizeof(ratchet));
    memset(state, 0, sizeof(state));
    memset(working, 0, sizeof(working));
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(buf, 0, sizeof(buf));
    memset(&hmac, 0, sizeof(hmac));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }
    fout = fopen(outpath, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open output file.\n");
        goto cleanup;
    }

    if (!get_file_size(fin, &original_size)) {
        fprintf(stderr, "Error: cannot determine input file size.\n");
        goto cleanup;
    }

    memcpy(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic));
    hdr.version = (uint8_t)HEADER_VERSION_V4;
    hdr.flags = 0;
    store_u32_le(hdr.chunk_size_le, CHUNK_SIZE_V4);
    store_u64_le(hdr.original_size_le, original_size);

    if (!fill_salt_nonce(hdr.salt, hdr.nonce, &hdr.flags)) {
        fprintf(stderr, "Error: random generation failed.\n");
        goto cleanup;
    }

    if (!derive_keys_v3(password, hdr.salt, enc_key, hmac_key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }

    memcpy(nonce_counter + 8, hdr.nonce, NONCE_LEN);
    nexus_arx_init_state(state, ARX_CONSTANTS, enc_key, nonce_counter);

    file_nonce_lo = load_u64_le(hdr.nonce);
    domain = compute_domain(hdr.version, hdr.flags, load_u32_le(hdr.chunk_size_le));
    if (!ratchet_seed(ratchet, &hdr, original_size, domain)) {
        fprintf(stderr, "Error: ratchet seed initialization failed.\n");
        goto cleanup;
    }

    if (fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to write header.\n");
        goto cleanup;
    }

    if (!hmac_stream_init(&hmac, hmac_key, HMAC_KEY_LEN)) {
        fprintf(stderr, "Error: HMAC init failed.\n");
        goto cleanup;
    }
    hmac_initialized = 1;

    if (!hmac_stream_update(&hmac, (const uint8_t *)&hdr, sizeof(hdr))) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t processed = 0;
        uint32_t feedback[4];
        uint32_t rekey1[4];
        uint32_t rekey2[4];
        uint32_t rat_words1[4];
        uint32_t rat_words2[4];
        uint8_t first16[16];
        uint8_t last16[16];
        uint32_t domain_i = domain ^ load_u32_le(ratchet);
        uint64_t nonce_mix = file_nonce_lo ^ load_u64_le(ratchet + 8);
        uint64_t size_mix = original_size ^ load_u64_le(ratchet + 16);

        nexus_arx_inject_tweak(state, chunk_index, nonce_mix, size_mix, domain_i);

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
        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "Error: failed to write ciphertext.\n");
            goto cleanup;
        }

        sample_chunk_edges(buf, n, first16, last16);
        extract_feedback(buf, n, feedback);
        memcpy(rat_words1, ratchet, 16);
        memcpy(rat_words2, ratchet + 16, 16);
        for (int i = 0; i < 4; i++) {
            rekey1[i] = feedback[i] ^ rat_words1[i];
            rekey2[i] = feedback[i] + rat_words2[i];
        }
        nexus_arx_rekey(state, rekey1);
        nexus_arx_rekey(state, rekey2);
        if (!ratchet_step(ratchet, chunk_index, domain_i, n, first16, last16, feedback)) {
            fprintf(stderr, "Error: ratchet update failed.\n");
            goto cleanup;
        }

        nexus_arx_wipe(feedback, sizeof(feedback));
        nexus_arx_wipe(rekey1, sizeof(rekey1));
        nexus_arx_wipe(rekey2, sizeof(rekey2));
        nexus_arx_wipe(rat_words1, sizeof(rat_words1));
        nexus_arx_wipe(rat_words2, sizeof(rat_words2));
        nexus_arx_wipe(first16, sizeof(first16));
        nexus_arx_wipe(last16, sizeof(last16));

        chunk_index++;
    }

    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during encryption.\n");
        goto cleanup;
    }

    if (!hmac_stream_final(&hmac, hdr.hmac_tag)) {
        fprintf(stderr, "Error: HMAC finalize failed.\n");
        goto cleanup;
    }

    if (fseek(fout, 0, SEEK_SET) != 0 || fwrite(&hdr, sizeof(hdr), 1, fout) != 1) {
        fprintf(stderr, "Error: failed to finalize header.\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (hmac_initialized) {
        hmac_stream_cleanup(&hmac);
    }
    nexus_arx_wipe(enc_key, sizeof(enc_key));
    nexus_arx_wipe(hmac_key, sizeof(hmac_key));
    nexus_arx_wipe(ratchet, sizeof(ratchet));
    nexus_arx_wipe(state, sizeof(state));
    nexus_arx_wipe(working, sizeof(working));
    nexus_arx_wipe(nonce_counter, sizeof(nonce_counter));
    nexus_arx_wipe(buf, sizeof(buf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (fin != NULL) {
        fclose(fin);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    return rc;
}

/* ---------- Decrypt v2 ---------- */
static int do_decrypt_v2(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    FileHeader hdr;
    uint8_t key[KEY_LEN];
    uint8_t iv[AEAD_IV_LEN];
    uint8_t expected_tag[AEAD_TAG_LEN];
    uint8_t inbuf[CHUNK_SIZE];
    uint8_t outbuf[CHUNK_SIZE + AEAD_TAG_LEN];
    uint64_t original_size = 0;
    uint64_t plaintext_written = 0;

    char *tmp_path = NULL;

    memset(&hdr, 0, sizeof(hdr));
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(expected_tag, 0, sizeof(expected_tag));
    memset(inbuf, 0, sizeof(inbuf));
    memset(outbuf, 0, sizeof(outbuf));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }

    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "Error: invalid or truncated file.\n");
        goto cleanup;
    }
    if (memcmp(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic)) != 0 || hdr.version != HEADER_VERSION_V2) {
        fprintf(stderr, "Error: not a supported v2 file.\n");
        goto cleanup;
    }
    if (load_u32_le(hdr.chunk_size_le) != CHUNK_SIZE) {
        fprintf(stderr, "Error: unsupported chunk size.\n");
        goto cleanup;
    }
    original_size = load_u64_le(hdr.original_size_le);

    if (!derive_key_v2(password, hdr.salt, key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }
    build_v2_iv(iv, hdr.nonce);
    memcpy(expected_tag, hdr.hmac_tag, AEAD_TAG_LEN);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: cipher context allocation failed.\n");
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, AEAD_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        fprintf(stderr, "Error: AEAD initialization failed.\n");
        goto cleanup;
    }

    {
        int aad_len = 0;
        if (EVP_DecryptUpdate(ctx, NULL, &aad_len, (const uint8_t *)&hdr, HEADER_AAD_LEN) != 1) {
            fprintf(stderr, "Error: AEAD header binding failed.\n");
            goto cleanup;
        }
    }

    {
        size_t need = strlen(outpath) + 32u;
        tmp_path = (char *)malloc(need);
        if (tmp_path == NULL) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            goto cleanup;
        }
        snprintf(tmp_path, need, "%s.tmp.%ld", outpath, (long)getpid());
    }

    fout = fopen(tmp_path, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open temporary output file.\n");
        goto cleanup;
    }

    while (1) {
        size_t n = fread(inbuf, 1, sizeof(inbuf), fin);
        int out_len = 0;

        if (n > 0) {
            if (EVP_DecryptUpdate(ctx, outbuf, &out_len, inbuf, (int)n) != 1) {
                fprintf(stderr, "Error: decryption failed.\n");
                goto cleanup;
            }
            if (out_len > 0) {
                if (fwrite(outbuf, 1, (size_t)out_len, fout) != (size_t)out_len) {
                    fprintf(stderr, "Error: failed to write plaintext.\n");
                    goto cleanup;
                }
                plaintext_written += (uint64_t)out_len;
            }
        }

        if (n < sizeof(inbuf)) {
            if (ferror(fin)) {
                fprintf(stderr, "Error: read failure during decryption.\n");
                goto cleanup;
            }
            break;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, expected_tag) != 1) {
        fprintf(stderr, "Error: failed to set authentication tag.\n");
        goto cleanup;
    }

    {
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, outbuf, &final_len) != 1) {
            fprintf(stderr, "Error: authentication failed (wrong password or tampered file).\n");
            goto cleanup;
        }
        if (final_len > 0) {
            if (fwrite(outbuf, 1, (size_t)final_len, fout) != (size_t)final_len) {
                fprintf(stderr, "Error: failed to write plaintext.\n");
                goto cleanup;
            }
            plaintext_written += (uint64_t)final_len;
        }
    }

    if (plaintext_written != original_size) {
        fprintf(stderr, "Error: decrypted size mismatch.\n");
        goto cleanup;
    }

    if (fflush(fout) != 0) {
        fprintf(stderr, "Error: flush failed for output file.\n");
        goto cleanup;
    }

    if (fclose(fout) != 0) {
        fout = NULL;
        fprintf(stderr, "Error: failed to close output file.\n");
        goto cleanup;
    }
    fout = NULL;

    if (rename(tmp_path, outpath) != 0) {
        fprintf(stderr, "Error: failed to finalize output file: %s\n", strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (fout != NULL) {
        fclose(fout);
    }
    if (rc != 0 && tmp_path != NULL) {
        remove(tmp_path);
    }

    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }

    nexus_arx_wipe(key, sizeof(key));
    nexus_arx_wipe(iv, sizeof(iv));
    nexus_arx_wipe(expected_tag, sizeof(expected_tag));
    nexus_arx_wipe(inbuf, sizeof(inbuf));
    nexus_arx_wipe(outbuf, sizeof(outbuf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (tmp_path != NULL) {
        size_t tmp_len = strlen(tmp_path);
        nexus_arx_wipe(tmp_path, tmp_len);
        free(tmp_path);
    }

    if (fin != NULL) {
        fclose(fin);
    }

    return rc;
}

/* ---------- Decrypt v4 (trajectory-coupled experimental ARX mode) ---------- */
static int do_decrypt_v4(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    HmacStream hmac;
    int hmac_initialized = 0;

    FileHeader hdr;
    uint8_t enc_key[KEY_LEN];
    uint8_t hmac_key[HMAC_KEY_LEN];
    uint8_t saved_tag[HMAC_TAG_LEN];
    uint8_t computed_tag[HMAC_TAG_LEN];
    uint8_t ratchet[32];
    uint32_t state[16];
    uint32_t working[16];
    uint8_t nonce_counter[16];
    uint8_t buf[CHUNK_SIZE_V4];
    size_t n = 0;
    uint64_t chunk_index = 0;
    uint64_t original_size = 0;
    uint64_t file_nonce_lo = 0;
    uint64_t plaintext_written = 0;
    uint32_t header_chunk_size = 0;
    uint32_t domain = 0;
    char *tmp_path = NULL;

    memset(&hdr, 0, sizeof(hdr));
    memset(enc_key, 0, sizeof(enc_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(saved_tag, 0, sizeof(saved_tag));
    memset(computed_tag, 0, sizeof(computed_tag));
    memset(ratchet, 0, sizeof(ratchet));
    memset(state, 0, sizeof(state));
    memset(working, 0, sizeof(working));
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(buf, 0, sizeof(buf));
    memset(&hmac, 0, sizeof(hmac));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }

    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "Error: invalid or truncated file.\n");
        goto cleanup;
    }
    if (memcmp(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic)) != 0) {
        fprintf(stderr, "Error: not a Nexus-ARX-T encrypted file.\n");
        goto cleanup;
    }
    if (hdr.version != HEADER_VERSION_V4) {
        fprintf(stderr, "Error: unsupported experimental header version %u.\n", (unsigned)hdr.version);
        goto cleanup;
    }

    header_chunk_size = load_u32_le(hdr.chunk_size_le);
    if (header_chunk_size != CHUNK_SIZE_V4) {
        fprintf(stderr, "Error: unsupported experimental chunk size %u.\n", header_chunk_size);
        goto cleanup;
    }
    original_size = load_u64_le(hdr.original_size_le);

    if (!derive_keys_v3(password, hdr.salt, enc_key, hmac_key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }

    memcpy(saved_tag, hdr.hmac_tag, HMAC_TAG_LEN);
    memset(hdr.hmac_tag, 0, HMAC_TAG_LEN);

    if (!hmac_stream_init(&hmac, hmac_key, HMAC_KEY_LEN)) {
        fprintf(stderr, "Error: HMAC init failed.\n");
        goto cleanup;
    }
    hmac_initialized = 1;

    if (!hmac_stream_update(&hmac, (const uint8_t *)&hdr, sizeof(hdr))) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        goto cleanup;
    }

    {
        size_t need = strlen(outpath) + 32u;
        tmp_path = (char *)malloc(need);
        if (tmp_path == NULL) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            goto cleanup;
        }
        snprintf(tmp_path, need, "%s.tmp.%ld", outpath, (long)getpid());
    }

    fout = fopen(tmp_path, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open temporary output file.\n");
        goto cleanup;
    }

    memcpy(nonce_counter + 8, hdr.nonce, NONCE_LEN);
    nexus_arx_init_state(state, ARX_CONSTANTS, enc_key, nonce_counter);

    file_nonce_lo = load_u64_le(hdr.nonce);
    domain = compute_domain(hdr.version, hdr.flags, header_chunk_size);
    if (!ratchet_seed(ratchet, &hdr, original_size, domain)) {
        fprintf(stderr, "Error: ratchet seed initialization failed.\n");
        goto cleanup;
    }

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t processed = 0;
        uint32_t feedback[4];
        uint32_t rekey1[4];
        uint32_t rekey2[4];
        uint32_t rat_words1[4];
        uint32_t rat_words2[4];
        uint8_t first16[16];
        uint8_t last16[16];
        uint32_t domain_i = domain ^ load_u32_le(ratchet);
        uint64_t nonce_mix = file_nonce_lo ^ load_u64_le(ratchet + 8);
        uint64_t size_mix = original_size ^ load_u64_le(ratchet + 16);

        if (!hmac_stream_update(&hmac, buf, n)) {
            fprintf(stderr, "Error: HMAC update failed.\n");
            goto cleanup;
        }

        sample_chunk_edges(buf, n, first16, last16);
        extract_feedback(buf, n, feedback);

        nexus_arx_inject_tweak(state, chunk_index, nonce_mix, size_mix, domain_i);
        while (processed < n) {
            size_t take = n - processed;
            if (take > BLOCK_SIZE) {
                take = BLOCK_SIZE;
            }
            nexus_arx_generate_block(working, state);
            xor_bytes(buf + processed, (const uint8_t *)working, take);
            processed += take;
        }

        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "Error: failed to write plaintext.\n");
            goto cleanup;
        }

        memcpy(rat_words1, ratchet, 16);
        memcpy(rat_words2, ratchet + 16, 16);
        for (int i = 0; i < 4; i++) {
            rekey1[i] = feedback[i] ^ rat_words1[i];
            rekey2[i] = feedback[i] + rat_words2[i];
        }
        nexus_arx_rekey(state, rekey1);
        nexus_arx_rekey(state, rekey2);
        if (!ratchet_step(ratchet, chunk_index, domain_i, n, first16, last16, feedback)) {
            fprintf(stderr, "Error: ratchet update failed.\n");
            goto cleanup;
        }

        nexus_arx_wipe(feedback, sizeof(feedback));
        nexus_arx_wipe(rekey1, sizeof(rekey1));
        nexus_arx_wipe(rekey2, sizeof(rekey2));
        nexus_arx_wipe(rat_words1, sizeof(rat_words1));
        nexus_arx_wipe(rat_words2, sizeof(rat_words2));
        nexus_arx_wipe(first16, sizeof(first16));
        nexus_arx_wipe(last16, sizeof(last16));

        plaintext_written += (uint64_t)n;
        chunk_index++;
    }

    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during decryption.\n");
        goto cleanup;
    }
    if (plaintext_written != original_size) {
        fprintf(stderr, "Error: decrypted size mismatch.\n");
        goto cleanup;
    }

    if (!hmac_stream_final(&hmac, computed_tag)) {
        fprintf(stderr, "Error: HMAC finalize failed.\n");
        goto cleanup;
    }
    if (CRYPTO_memcmp(computed_tag, saved_tag, HMAC_TAG_LEN) != 0) {
        fprintf(stderr, "Error: authentication failed (wrong password or tampered file).\n");
        goto cleanup;
    }

    if (fflush(fout) != 0) {
        fprintf(stderr, "Error: flush failed for output file.\n");
        goto cleanup;
    }
    if (fclose(fout) != 0) {
        fout = NULL;
        fprintf(stderr, "Error: failed to close output file.\n");
        goto cleanup;
    }
    fout = NULL;

    if (rename(tmp_path, outpath) != 0) {
        fprintf(stderr, "Error: failed to finalize output file: %s\n", strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (hmac_initialized) {
        hmac_stream_cleanup(&hmac);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    if (rc != 0 && tmp_path != NULL) {
        remove(tmp_path);
    }

    nexus_arx_wipe(enc_key, sizeof(enc_key));
    nexus_arx_wipe(hmac_key, sizeof(hmac_key));
    nexus_arx_wipe(saved_tag, sizeof(saved_tag));
    nexus_arx_wipe(computed_tag, sizeof(computed_tag));
    nexus_arx_wipe(ratchet, sizeof(ratchet));
    nexus_arx_wipe(state, sizeof(state));
    nexus_arx_wipe(working, sizeof(working));
    nexus_arx_wipe(nonce_counter, sizeof(nonce_counter));
    nexus_arx_wipe(buf, sizeof(buf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (tmp_path != NULL) {
        size_t tmp_len = strlen(tmp_path);
        nexus_arx_wipe(tmp_path, tmp_len);
        free(tmp_path);
    }

    if (fin != NULL) {
        fclose(fin);
    }
    return rc;
}

/* ---------- Decrypt v3 (experimental ARX mode) ---------- */
static int do_decrypt_v3(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    HmacStream hmac;
    int hmac_initialized = 0;

    FileHeader hdr;
    uint8_t enc_key[KEY_LEN];
    uint8_t hmac_key[HMAC_KEY_LEN];
    uint8_t saved_tag[HMAC_TAG_LEN];
    uint8_t computed_tag[HMAC_TAG_LEN];
    uint32_t state[16];
    uint32_t working[16];
    uint8_t nonce_counter[16];
    uint8_t buf[CHUNK_SIZE_V3];
    size_t n = 0;
    uint64_t chunk_index = 0;
    uint64_t original_size = 0;
    uint64_t file_nonce_lo = 0;
    uint64_t plaintext_written = 0;
    uint32_t header_chunk_size = 0;
    uint32_t domain = 0;
    char *tmp_path = NULL;

    memset(&hdr, 0, sizeof(hdr));
    memset(enc_key, 0, sizeof(enc_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(saved_tag, 0, sizeof(saved_tag));
    memset(computed_tag, 0, sizeof(computed_tag));
    memset(state, 0, sizeof(state));
    memset(working, 0, sizeof(working));
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(buf, 0, sizeof(buf));
    memset(&hmac, 0, sizeof(hmac));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }

    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "Error: invalid or truncated file.\n");
        goto cleanup;
    }
    if (memcmp(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic)) != 0) {
        fprintf(stderr, "Error: not a Nexus-ARX-T encrypted file.\n");
        goto cleanup;
    }
    if (hdr.version != HEADER_VERSION_V3) {
        fprintf(stderr, "Error: unsupported experimental header version %u.\n", (unsigned)hdr.version);
        goto cleanup;
    }

    header_chunk_size = load_u32_le(hdr.chunk_size_le);
    if (header_chunk_size != CHUNK_SIZE_V3) {
        fprintf(stderr, "Error: unsupported experimental chunk size %u.\n", header_chunk_size);
        goto cleanup;
    }
    original_size = load_u64_le(hdr.original_size_le);

    if (!derive_keys_v3(password, hdr.salt, enc_key, hmac_key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }

    memcpy(saved_tag, hdr.hmac_tag, HMAC_TAG_LEN);
    memset(hdr.hmac_tag, 0, HMAC_TAG_LEN);

    if (!hmac_stream_init(&hmac, hmac_key, HMAC_KEY_LEN)) {
        fprintf(stderr, "Error: HMAC init failed.\n");
        goto cleanup;
    }
    hmac_initialized = 1;

    if (!hmac_stream_update(&hmac, (const uint8_t *)&hdr, sizeof(hdr))) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        goto cleanup;
    }

    {
        size_t need = strlen(outpath) + 32u;
        tmp_path = (char *)malloc(need);
        if (tmp_path == NULL) {
            fprintf(stderr, "Error: memory allocation failed.\n");
            goto cleanup;
        }
        snprintf(tmp_path, need, "%s.tmp.%ld", outpath, (long)getpid());
    }

    fout = fopen(tmp_path, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open temporary output file.\n");
        goto cleanup;
    }

    memcpy(nonce_counter + 8, hdr.nonce, NONCE_LEN);
    nexus_arx_init_state(state, ARX_CONSTANTS, enc_key, nonce_counter);

    file_nonce_lo = load_u64_le(hdr.nonce);
    domain = compute_domain(hdr.version, hdr.flags, header_chunk_size);

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t processed = 0;
        uint32_t feedback[4];

        if (!hmac_stream_update(&hmac, buf, n)) {
            fprintf(stderr, "Error: HMAC update failed.\n");
            goto cleanup;
        }

        extract_feedback(buf, n, feedback);
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

        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "Error: failed to write plaintext.\n");
            nexus_arx_wipe(feedback, sizeof(feedback));
            goto cleanup;
        }

        nexus_arx_rekey(state, feedback);
        nexus_arx_wipe(feedback, sizeof(feedback));

        plaintext_written += (uint64_t)n;
        chunk_index++;
    }

    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during decryption.\n");
        goto cleanup;
    }
    if (plaintext_written != original_size) {
        fprintf(stderr, "Error: decrypted size mismatch.\n");
        goto cleanup;
    }

    if (!hmac_stream_final(&hmac, computed_tag)) {
        fprintf(stderr, "Error: HMAC finalize failed.\n");
        goto cleanup;
    }
    if (CRYPTO_memcmp(computed_tag, saved_tag, HMAC_TAG_LEN) != 0) {
        fprintf(stderr, "Error: authentication failed (wrong password or tampered file).\n");
        goto cleanup;
    }

    if (fflush(fout) != 0) {
        fprintf(stderr, "Error: flush failed for output file.\n");
        goto cleanup;
    }
    if (fclose(fout) != 0) {
        fout = NULL;
        fprintf(stderr, "Error: failed to close output file.\n");
        goto cleanup;
    }
    fout = NULL;

    if (rename(tmp_path, outpath) != 0) {
        fprintf(stderr, "Error: failed to finalize output file: %s\n", strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (hmac_initialized) {
        hmac_stream_cleanup(&hmac);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    if (rc != 0 && tmp_path != NULL) {
        remove(tmp_path);
    }

    nexus_arx_wipe(enc_key, sizeof(enc_key));
    nexus_arx_wipe(hmac_key, sizeof(hmac_key));
    nexus_arx_wipe(saved_tag, sizeof(saved_tag));
    nexus_arx_wipe(computed_tag, sizeof(computed_tag));
    nexus_arx_wipe(state, sizeof(state));
    nexus_arx_wipe(working, sizeof(working));
    nexus_arx_wipe(nonce_counter, sizeof(nonce_counter));
    nexus_arx_wipe(buf, sizeof(buf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (tmp_path != NULL) {
        size_t tmp_len = strlen(tmp_path);
        nexus_arx_wipe(tmp_path, tmp_len);
        free(tmp_path);
    }

    if (fin != NULL) {
        fclose(fin);
    }
    return rc;
}

/* ---------- Decrypt v1 (legacy compatibility) ---------- */
static int do_decrypt_v1(const char *inpath, const char *outpath, const char *password) {
    int rc = 1;
    FILE *fin = NULL;
    FILE *fout = NULL;
    HmacStream hmac;
    int hmac_initialized = 0;

    FileHeader hdr;
    uint8_t enc_key[KEY_LEN];
    uint8_t hmac_key[HMAC_KEY_LEN];
    uint8_t saved_tag[HMAC_TAG_LEN];
    uint8_t computed_tag[HMAC_TAG_LEN];
    uint32_t state[16];
    uint32_t working[16];
    uint8_t nonce_counter[16];
    uint8_t verify_buf[CHUNK_SIZE];
    uint8_t buf[CHUNK_SIZE];
    size_t n = 0;
    uint64_t chunk_index = 0;
    uint64_t original_size = 0;
    uint64_t file_nonce_lo = 0;
    uint64_t plaintext_written = 0;
    uint32_t header_chunk_size = 0;
    uint32_t domain = 0;

    memset(&hdr, 0, sizeof(hdr));
    memset(enc_key, 0, sizeof(enc_key));
    memset(hmac_key, 0, sizeof(hmac_key));
    memset(saved_tag, 0, sizeof(saved_tag));
    memset(computed_tag, 0, sizeof(computed_tag));
    memset(state, 0, sizeof(state));
    memset(working, 0, sizeof(working));
    memset(nonce_counter, 0, sizeof(nonce_counter));
    memset(verify_buf, 0, sizeof(verify_buf));
    memset(buf, 0, sizeof(buf));
    memset(&hmac, 0, sizeof(hmac));

    fin = fopen(inpath, "rb");
    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        goto cleanup;
    }

    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "Error: invalid or truncated file.\n");
        goto cleanup;
    }
    if (memcmp(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic)) != 0) {
        fprintf(stderr, "Error: not a Nexus-ARX-T encrypted file.\n");
        goto cleanup;
    }
    if (hdr.version != HEADER_VERSION_V1) {
        fprintf(stderr, "Error: unsupported legacy header version %u.\n", (unsigned)hdr.version);
        goto cleanup;
    }

    header_chunk_size = load_u32_le(hdr.chunk_size_le);
    if (header_chunk_size != CHUNK_SIZE) {
        fprintf(stderr, "Error: unsupported chunk size %u.\n", header_chunk_size);
        goto cleanup;
    }
    original_size = load_u64_le(hdr.original_size_le);

    if (!derive_keys_v1(password, hdr.salt, enc_key, hmac_key)) {
        fprintf(stderr, "Error: key derivation failed.\n");
        goto cleanup;
    }

    memcpy(saved_tag, hdr.hmac_tag, HMAC_TAG_LEN);
    memset(hdr.hmac_tag, 0, HMAC_TAG_LEN);

    if (!hmac_stream_init(&hmac, hmac_key, HMAC_KEY_LEN)) {
        fprintf(stderr, "Error: HMAC init failed.\n");
        goto cleanup;
    }
    hmac_initialized = 1;

    if (!hmac_stream_update(&hmac, (const uint8_t *)&hdr, sizeof(hdr))) {
        fprintf(stderr, "Error: HMAC update failed.\n");
        goto cleanup;
    }

    while ((n = fread(verify_buf, 1, sizeof(verify_buf), fin)) > 0) {
        if (!hmac_stream_update(&hmac, verify_buf, n)) {
            fprintf(stderr, "Error: HMAC update failed.\n");
            goto cleanup;
        }
    }
    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during authentication.\n");
        goto cleanup;
    }
    if (!hmac_stream_final(&hmac, computed_tag)) {
        fprintf(stderr, "Error: HMAC finalize failed.\n");
        goto cleanup;
    }
    if (CRYPTO_memcmp(computed_tag, saved_tag, HMAC_TAG_LEN) != 0) {
        fprintf(stderr, "Error: authentication failed (wrong password or tampered file).\n");
        goto cleanup;
    }

    if (fseek(fin, (long)sizeof(FileHeader), SEEK_SET) != 0) {
        fprintf(stderr, "Error: unable to seek to ciphertext.\n");
        goto cleanup;
    }

    fout = fopen(outpath, "wb");
    if (fout == NULL) {
        fprintf(stderr, "Error: cannot open output file.\n");
        goto cleanup;
    }

    memcpy(nonce_counter + 8, hdr.nonce, NONCE_LEN);
    nexus_arx_init_state(state, ARX_CONSTANTS, enc_key, nonce_counter);

    file_nonce_lo = load_u64_le(hdr.nonce);
    domain = compute_domain(hdr.version, hdr.flags, header_chunk_size);

    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        size_t processed = 0;
        uint32_t feedback[4];

        /* feedback must come from ciphertext before XOR */
        extract_feedback(buf, n, feedback);
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

        if (fwrite(buf, 1, n, fout) != n) {
            fprintf(stderr, "Error: failed to write plaintext.\n");
            nexus_arx_wipe(feedback, sizeof(feedback));
            goto cleanup;
        }

        nexus_arx_rekey(state, feedback);
        nexus_arx_wipe(feedback, sizeof(feedback));

        plaintext_written += (uint64_t)n;
        chunk_index++;
    }

    if (ferror(fin)) {
        fprintf(stderr, "Error: read failure during decryption.\n");
        goto cleanup;
    }
    if (plaintext_written != original_size) {
        fprintf(stderr, "Error: decrypted size mismatch.\n");
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (hmac_initialized) {
        hmac_stream_cleanup(&hmac);
    }
    nexus_arx_wipe(enc_key, sizeof(enc_key));
    nexus_arx_wipe(hmac_key, sizeof(hmac_key));
    nexus_arx_wipe(saved_tag, sizeof(saved_tag));
    nexus_arx_wipe(computed_tag, sizeof(computed_tag));
    nexus_arx_wipe(state, sizeof(state));
    nexus_arx_wipe(working, sizeof(working));
    nexus_arx_wipe(nonce_counter, sizeof(nonce_counter));
    nexus_arx_wipe(verify_buf, sizeof(verify_buf));
    nexus_arx_wipe(buf, sizeof(buf));
    nexus_arx_wipe(&hdr, sizeof(hdr));

    if (fin != NULL) {
        fclose(fin);
    }
    if (fout != NULL) {
        fclose(fout);
    }
    return rc;
}

/* ---------- Decrypt Dispatcher ---------- */
static int do_decrypt(const char *inpath, const char *outpath, const char *password) {
    FILE *fin = fopen(inpath, "rb");
    FileHeader hdr;
    int rc = 1;

    if (fin == NULL) {
        fprintf(stderr, "Error: cannot open input file.\n");
        return 1;
    }

    memset(&hdr, 0, sizeof(hdr));
    if (fread(&hdr, sizeof(hdr), 1, fin) != 1) {
        fprintf(stderr, "Error: invalid or truncated file.\n");
        fclose(fin);
        return 1;
    }
    fclose(fin);

    if (memcmp(hdr.magic, NEXUS_MAGIC, sizeof(hdr.magic)) != 0) {
        fprintf(stderr, "Error: not a Nexus-ARX-T encrypted file.\n");
        nexus_arx_wipe(&hdr, sizeof(hdr));
        return 1;
    }

    if (hdr.version == HEADER_VERSION_V2) {
        rc = do_decrypt_v2(inpath, outpath, password);
    } else if (hdr.version == HEADER_VERSION_V4) {
        rc = do_decrypt_v4(inpath, outpath, password);
    } else if (hdr.version == HEADER_VERSION_V3) {
        rc = do_decrypt_v3(inpath, outpath, password);
    } else if (hdr.version == HEADER_VERSION_V1) {
        rc = do_decrypt_v1(inpath, outpath, password);
    } else {
        fprintf(stderr, "Error: unsupported header version %u.\n", (unsigned)hdr.version);
        rc = 1;
    }

    nexus_arx_wipe(&hdr, sizeof(hdr));
    return rc;
}

/* ---------- CLI ---------- */
static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <E|D> <input> <output> [--pass-stdin] [--experimental] [--experimental-v3]\n", prog);
    fprintf(stderr, "Password sources (in order):\n");
    fprintf(stderr, "  1) env %s\n", PASSWORD_ENV);
    fprintf(stderr, "  2) --pass-stdin (read one line from stdin)\n");
    fprintf(stderr, "  3) hidden TTY prompt\n");
    fprintf(stderr, "Encryption profiles:\n");
    fprintf(stderr, "  default: v2 (ChaCha20-Poly1305 + scrypt)\n");
    fprintf(stderr, "  --experimental: v4 (trajectory-coupled ARX+tweak+dual-rekey ratchet + HMAC + scrypt)\n");
    fprintf(stderr, "  --experimental-v3: legacy v3 (custom ARX+tweak+rekey + HMAC + scrypt)\n");
    fprintf(stderr, "Set %s=1 for deterministic test-vector mode.\n", DETERMINISTIC_ENV);
}

int main(int argc, char *argv[]) {
    char mode;
    int pass_from_stdin = 0;
    int experimental_profile = 0; /* 0=v2, 3=v3, 4=v4 */
    char password[PASSWORD_MAX_LEN];
    int rc = 1;
    int i;

    memset(password, 0, sizeof(password));

    if (argc < 4 || argc > 6) {
        usage(argv[0]);
        return 1;
    }

    for (i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--pass-stdin") == 0) {
            pass_from_stdin = 1;
        } else if (strcmp(argv[i], "--experimental") == 0) {
            experimental_profile = 4;
        } else if (strcmp(argv[i], "--experimental-v3") == 0) {
            experimental_profile = 3;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (!acquire_password(pass_from_stdin, password)) {
        fprintf(stderr, "Error: failed to obtain password. Use %s or --pass-stdin.\n", PASSWORD_ENV);
        nexus_arx_wipe(password, sizeof(password));
        return 1;
    }

    mode = argv[1][0];
    if (mode == 'E' || mode == 'e') {
        if (experimental_profile == 4) {
            rc = do_encrypt_v4(argv[2], argv[3], password);
        } else if (experimental_profile == 3) {
            rc = do_encrypt_v3(argv[2], argv[3], password);
        } else {
            rc = do_encrypt_v2(argv[2], argv[3], password);
        }
    } else if (mode == 'D' || mode == 'd') {
        rc = do_decrypt(argv[2], argv[3], password);
    } else {
        fprintf(stderr, "Error: mode must be E or D.\n");
        usage(argv[0]);
        rc = 1;
    }

    nexus_arx_wipe(password, sizeof(password));
    return rc;
}
