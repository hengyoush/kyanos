#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
BEFORE_LNAME="${FILE_PREFIX}_filter_by_comm_before.log"
AFTER_LNAME="${FILE_PREFIX}_filter_by_comm_after.log"

function test_filter_by_comm() {
    openssl req -x509 -newkey rsa:2048 -keyout server.pem -out server.pem -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost"

    pip install --break-system-packages ssl || true

    # server start before kyanos
    timeout 40 python3 ./testdata/start_https_server.py  &
    timeout 30 ${CMD} watch --debug-output http --comm python3 2>&1 | tee "${BEFORE_LNAME}" &
    sleep 10
    curl --insecure https://127.0.0.1:4443 &>/dev/null || true
    wait

    cat "${BEFORE_LNAME}" | grep "127.0.0.1:4443"

    # server start after kyanos
    timeout 40 ${CMD} watch --debug-output http --comm python3 2>&1 | tee "${AFTER_LNAME}" &
    timeout 30 python3 ./testdata/start_https_server.py  &
    sleep 10
    curl --insecure https://127.0.0.1:4443 &>/dev/null || true
    wait

    cat "${AFTER_LNAME}" | grep "127.0.0.1:4443"
}

function main() {
    test_filter_by_comm
}

main