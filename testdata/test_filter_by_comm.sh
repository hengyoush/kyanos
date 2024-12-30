#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
BEFORE_LNAME="${FILE_PREFIX}_filter_by_comm_before.log"
AFTER_LNAME="${FILE_PREFIX}_filter_by_comm_after.log"

function test_filter_by_comm() {
    # server start before kyanos
    timeout 40 python3 ./testdata/start_http_server.py  &
    timeout 30 ${CMD} watch --debug-output http --comm python3 2>&1 | tee "${BEFORE_LNAME}" &
    sleep 10
    curl http://127.0.0.1:8080 &>/dev/null || true
    wait

    cat "${BEFORE_LNAME}"
    cat "${BEFORE_LNAME}" | grep "Host: 127.0.0.1:8080" | grep "\\[side\\]=server"

    # client start after kyanos
    timeout 40 ${CMD} watch --debug-output http --comm curl 2>&1 | tee "${AFTER_LNAME}" &
    sleep 10
    curl http://github.com &>/dev/null || true
    wait

    cat "${AFTER_LNAME}"
    cat "${AFTER_LNAME}" | grep "Host: github.com" | grep "\\[side\\]=client"
}

function main() {
    test_filter_by_comm
}

main