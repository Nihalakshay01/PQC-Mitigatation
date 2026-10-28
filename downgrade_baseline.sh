#!/usr/bin/env bash
set -u

CERT="$HOME/pqc-project/certs/server.crt"
KEY="$HOME/pqc-project/certs/server.key"
LOG="$HOME/pqc-project/logs"

run_test() {
    local name="$1"
    local server_groups="$2"
    local client_groups="$3"

    echo
    echo "=========================================="
    echo "TEST: $name"
    echo "Server groups: $server_groups"
    echo "Client groups: $client_groups"
    echo "=========================================="

    openssl s_server \
        -accept 4433 \
        -cert "$CERT" \
        -key "$KEY" \
        -groups "$server_groups" \
        -tls1_3 -www \
        > "$LOG/${name}_server.log" 2>&1 &
    SERVER_PID=$!

    sleep 2

    timeout 8 bash -c \
        "printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client \
        -connect 127.0.0.1:4433 \
        -groups '$client_groups' \
        -tls1_3 -brief" \
        > "$LOG/${name}_client.log" 2>&1
    CLIENT_STATUS=$?

    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    sleep 1

    if grep -q "Protocol version: TLSv1.3" "$LOG/${name}_client.log"; then
        echo "Result: TLS 1.3 handshake succeeded"
    elif grep -qiE "handshake failure|no suitable key share|no shared group" \
        "$LOG/${name}_client.log"; then
        echo "Result: Handshake failed as expected for incompatible groups"
    else
        echo "Result: Inspect client log (exit status $CLIENT_STATUS)"
    fi

    echo "--- Client evidence ---"
    grep -iE "Protocol version|Ciphersuite|Negotiated TLS|handshake failure|no suitable key share|no shared group|error" \
        "$LOG/${name}_client.log" || true

    echo "--- Server evidence ---"
    grep -iE "Negotiated TLS|Shared groups|handshake failure|error" \
        "$LOG/${name}_server.log" || true
}

# Test A: hybrid-only client against a classical-only server.
run_test "hybrid_only_vs_classical" \
    "X25519" "X25519MLKEM768"

# Test B: client permits hybrid and classical, but server only offers classical.
run_test "permitted_fallback_baseline" \
    "X25519" "X25519MLKEM768:X25519"

echo
echo "Logs saved in: $LOG"
