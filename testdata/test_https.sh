#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTPS_LNAME="${FILE_PREFIX}_https.log"

function test_http_plain_client() {
    pip install --break-system-packages requests || true
    timeout 30 python3 ./testdata/request_https.py 60 &
    sleep 10
    timeout 30 ${CMD} watch --debug-output http --remote-ports 443 2>&1 | tee "${HTTPS_LNAME}" &
    wait

    cat "${HTTPS_LNAME}"

    # check_time_detail_completed_with_last_lines "${HTTPS_LNAME}" 2
    cat "${HTTPS_LNAME}" | grep "httpbin"
}

function main() {
    test_http_plain_client
}

main
