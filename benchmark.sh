#!/bin/bash
set -euo pipefail

PASSWORD="BenchmarkPassword2026!"
SIZES_MB=(1 5 20)
RUNS="${RUNS:-3}"
BENCH_DIR="${BENCH_DIR:-benchmark_artifacts}"
RESULTS_FILE="${BENCH_DIR}/benchmark_results.tsv"

to_seconds() {
    awk "BEGIN { printf \"%.6f\", $1 / 1000000000 }"
}

throughput_mbps() {
    local bytes="$1"
    local seconds="$2"
    awk "BEGIN { if ($seconds <= 0.0) print \"inf\"; else printf \"%.2f\", ($bytes / 1048576.0) / $seconds }"
}

measure_cmd_ns() {
    local start_ns end_ns
    start_ns=$(date +%s%N)
    "$@" >/dev/null 2>&1
    end_ns=$(date +%s%N)
    echo $((end_ns - start_ns))
}

average_ns_for_cmd() {
    local runs="$1"
    shift
    local total_ns=0
    local run ns
    for run in $(seq 1 "$runs"); do
        ns=$(measure_cmd_ns "$@")
        total_ns=$((total_ns + ns))
    done
    echo $((total_ns / runs))
}

echo "=== Nexus-ARX-T Benchmark ==="
echo "[1/3] Build backend..."
nasm -f elf64 nexus_arx_core.asm -o nexus_arx_core.o
gcc -O3 -DNDEBUG -c nexus_arx_t.c -o nexus_arx_t.o $(pkg-config --cflags openssl)
gcc -O3 nexus_arx_t.o nexus_arx_core.o -o nexus_arx_t $(pkg-config --libs openssl)

echo "[2/3] Running throughput benchmarks (averaged over ${RUNS} runs)..."
mkdir -p "$BENCH_DIR"
printf "size_mb\truns\tnexus_std_enc_mb_s\tnexus_std_dec_mb_s\tnexus_exp_enc_mb_s\tnexus_exp_dec_mb_s\taes_ctr_enc_mb_s\taes_ctr_dec_mb_s\n" > "$RESULTS_FILE"
printf "%-8s %-6s %-16s %-16s %-16s %-16s %-16s %-16s\n" "Size" "Runs" "Std Enc MB/s" "Std Dec MB/s" "Exp Enc MB/s" "Exp Dec MB/s" "AES Enc MB/s" "AES Dec MB/s"

for mb in "${SIZES_MB[@]}"; do
    in_file="${BENCH_DIR}/bench_${mb}m_input.bin"
    nx_std_enc="${BENCH_DIR}/bench_${mb}m_nexus_std.enc"
    nx_std_dec="${BENCH_DIR}/bench_${mb}m_nexus_std.dec"
    nx_exp_enc="${BENCH_DIR}/bench_${mb}m_nexus_exp.enc"
    nx_exp_dec="${BENCH_DIR}/bench_${mb}m_nexus_exp.dec"
    aes_enc="${BENCH_DIR}/bench_${mb}m_aes.enc"
    aes_dec="${BENCH_DIR}/bench_${mb}m_aes.dec"
    bytes=$((mb * 1024 * 1024))

    dd if=/dev/urandom of="$in_file" bs=1M count="$mb" status=none

    nx_std_avg_ns_enc=$(average_ns_for_cmd "$RUNS" env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "$in_file" "$nx_std_enc")
    nx_std_avg_ns_dec=$(average_ns_for_cmd "$RUNS" env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "$nx_std_enc" "$nx_std_dec")
    nx_std_sec_enc=$(to_seconds "$nx_std_avg_ns_enc")
    nx_std_sec_dec=$(to_seconds "$nx_std_avg_ns_dec")
    nx_std_enc_rate=$(throughput_mbps "$bytes" "$nx_std_sec_enc")
    nx_std_dec_rate=$(throughput_mbps "$bytes" "$nx_std_sec_dec")

    nx_exp_avg_ns_enc=$(average_ns_for_cmd "$RUNS" env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t E "$in_file" "$nx_exp_enc" --experimental)
    nx_exp_avg_ns_dec=$(average_ns_for_cmd "$RUNS" env NEXUS_ARX_PASSWORD="$PASSWORD" ./nexus_arx_t D "$nx_exp_enc" "$nx_exp_dec")
    nx_exp_sec_enc=$(to_seconds "$nx_exp_avg_ns_enc")
    nx_exp_sec_dec=$(to_seconds "$nx_exp_avg_ns_dec")
    nx_exp_enc_rate=$(throughput_mbps "$bytes" "$nx_exp_sec_enc")
    nx_exp_dec_rate=$(throughput_mbps "$bytes" "$nx_exp_sec_dec")

    aes_enc_rate="n/a"
    aes_dec_rate="n/a"
    if command -v openssl >/dev/null 2>&1; then
        aes_avg_ns_enc=$(average_ns_for_cmd "$RUNS" openssl enc -aes-256-ctr -pbkdf2 -in "$in_file" -out "$aes_enc" -pass pass:"$PASSWORD")
        aes_avg_ns_dec=$(average_ns_for_cmd "$RUNS" openssl enc -d -aes-256-ctr -pbkdf2 -in "$aes_enc" -out "$aes_dec" -pass pass:"$PASSWORD")
        aes_sec_enc=$(to_seconds "$aes_avg_ns_enc")
        aes_sec_dec=$(to_seconds "$aes_avg_ns_dec")
        aes_enc_rate=$(throughput_mbps "$bytes" "$aes_sec_enc")
        aes_dec_rate=$(throughput_mbps "$bytes" "$aes_sec_dec")
    fi

    printf "%-8s %-6s %-16s %-16s %-16s %-16s %-16s %-16s\n" "${mb}MB" "$RUNS" "$nx_std_enc_rate" "$nx_std_dec_rate" "$nx_exp_enc_rate" "$nx_exp_dec_rate" "$aes_enc_rate" "$aes_dec_rate"
    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$mb" "$RUNS" "$nx_std_enc_rate" "$nx_std_dec_rate" "$nx_exp_enc_rate" "$nx_exp_dec_rate" "$aes_enc_rate" "$aes_dec_rate" >> "$RESULTS_FILE"
done

echo "[3/3] Done. Results saved to ${RESULTS_FILE}."
