#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTPS_LNAME="${FILE_PREFIX}_https.log"

function test_http_plain_client() {
    timeout 20 ${CMD} watch --debug-output http --remote-ports 443 2>&1 | tee "${HTTPS_LNAME}" &
    sleep 10
    python3 ./testdata/request_https.py 4 || true
    wait

    cat "${HTTPS_LNAME}"

    check_time_detail_completed_with_last_lines "${HTTPS_LNAME}" 2
    check_patterns_in_file_with_last_lines "${HTTPS_LNAME}" "httpbin" 2
}

function main() {
    test_http_plain_client
}

main
