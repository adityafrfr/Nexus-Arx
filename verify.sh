#!/bin/bash
set -euo pipefail

PASSWORD="MySecureTestPassword2026!"
WRONG_PASSWORD="WrongPassword"
HEADER_SIZE=78
VERIFY_DIR="${VERIFY_DIR:-verify_artifacts}"

expect_failure() {
    local description="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAILURE: ${description}"
        exit 1
    fi
}

echo "=== Nexus-ARX-T Verify Script ==="

echo "[1/13] Build backend..."
nasm -f elf64 nexus_arx_core.asm -o nexus_arx_core.o
gcc -O3 -DNDEBUG -c nexus_arx_t.c -o nexus_arx_t.o $(pkg-config --cflags openssl)
gcc -O3 nexus_arx_t.o nexus_arx_core.o -o nexus_arx_t $(pkg-config --libs openssl)

echo "[2/13] Create test plaintext fixtures..."
mkdir -p "$VERIFY_DIR"
cat > "${VERIFY_DIR}/original.txt" << 'EOF'
This is a secret message. It has multiple lines.
And some numbers: 1234567890
Special chars: @#$%^&*()_+-=[]{}|;':",./<>?
EOF
: > "${VERIFY_DIR}/empty.txt"

echo "[3/13] Encrypt + decrypt round-trip (standard v2)..."
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/encrypted.bin"
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/encrypted.bin" "${VERIFY_DIR}/decrypted.txt"
cmp -s "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/decrypted.txt"
echo " -> Round-trip success."

echo "[4/13] Empty-file round-trip..."
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/empty.txt" "${VERIFY_DIR}/empty.enc"
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/empty.enc" "${VERIFY_DIR}/empty.dec"
cmp -s "${VERIFY_DIR}/empty.txt" "${VERIFY_DIR}/empty.dec"
echo " -> Empty-file handling passed."

echo "[5/13] Wrong-password rejection..."
expect_failure "wrong password should not decrypt." \
    env NEXUS_ARX_PASSWORD="$WRONG_PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/encrypted.bin" "${VERIFY_DIR}/should_not_decrypt.txt"
echo " -> Wrong-password check passed."

echo "[6/13] Tamper detection..."
cp "${VERIFY_DIR}/encrypted.bin" "${VERIFY_DIR}/tampered.bin"
printf '\xAA' >> "${VERIFY_DIR}/tampered.bin"
expect_failure "tampered ciphertext should be rejected." \
    env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/tampered.bin" "${VERIFY_DIR}/should_not_tamper.txt"
echo " -> Tamper check passed."

echo "[7/13] Corrupted-header detection..."
cp "${VERIFY_DIR}/encrypted.bin" "${VERIFY_DIR}/bad_header.bin"
printf '\x00' | dd of="${VERIFY_DIR}/bad_header.bin" bs=1 seek=0 conv=notrunc status=none
expect_failure "corrupted header should be rejected." \
    env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/bad_header.bin" "${VERIFY_DIR}/should_not_header.txt"
echo " -> Header check passed."

echo "[8/13] Truncated-file detection..."
dd if="${VERIFY_DIR}/encrypted.bin" of="${VERIFY_DIR}/truncated.bin" bs=1 count=$((HEADER_SIZE + 10)) status=none
expect_failure "truncated ciphertext should be rejected." \
    env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/truncated.bin" "${VERIFY_DIR}/should_not_truncate.txt"
echo " -> Truncated-file check passed."

echo "[9/13] Deterministic test-vector mode reproducibility (standard v2)..."
env NEXUS_ARX_DETERMINISTIC=1 NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/deterministic_1.bin"
env NEXUS_ARX_DETERMINISTIC=1 NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/deterministic_2.bin"
cmp -s "${VERIFY_DIR}/deterministic_1.bin" "${VERIFY_DIR}/deterministic_2.bin"
echo " -> Deterministic mode reproducibility passed."

echo "[10/13] Deterministic-mode header flag validation..."
deterministic_flag=$(od -An -tx1 -j 9 -N 1 "${VERIFY_DIR}/deterministic_1.bin" | tr -d '[:space:]')
if [[ "$deterministic_flag" != "01" ]]; then
    echo "FAILURE: deterministic header flag was expected to be 01 but was ${deterministic_flag}."
    exit 1
fi
echo " -> Deterministic header flag passed."

echo "[11/13] Experimental mode round-trip..."
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/exp_encrypted.bin" --experimental
env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "${VERIFY_DIR}/exp_encrypted.bin" "${VERIFY_DIR}/exp_decrypted.txt"
cmp -s "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/exp_decrypted.txt"
echo " -> Experimental round-trip passed."

echo "[12/13] Experimental deterministic reproducibility..."
env NEXUS_ARX_DETERMINISTIC=1 NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/exp_deterministic_1.bin" --experimental
env NEXUS_ARX_DETERMINISTIC=1 NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "${VERIFY_DIR}/original.txt" "${VERIFY_DIR}/exp_deterministic_2.bin" --experimental
cmp -s "${VERIFY_DIR}/exp_deterministic_1.bin" "${VERIFY_DIR}/exp_deterministic_2.bin"
echo " -> Experimental deterministic mode passed."

echo "[13/13] Experimental header version validation..."
exp_version=$(od -An -tx1 -j 8 -N 1 "${VERIFY_DIR}/exp_encrypted.bin" | tr -d '[:space:]')
if [[ "$exp_version" != "04" ]]; then
    echo "FAILURE: experimental header version expected 04 but was ${exp_version}."
    exit 1
fi
echo " -> Experimental header version passed."

echo ""
echo "All verification checks passed."
