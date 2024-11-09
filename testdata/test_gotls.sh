#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
GOTLS_CLIENT_LNAME="${FILE_PREFIX}_gotls_client.log"
GOTLS_SERVER_LNAME="${FILE_PREFIX}_gotls_server.log"

function test_gotls_client() {
    timeout 30 ./testdata/https-request/https-request 'https://www.baidu.com' 40 &
    sleep 10
    timeout 30 ${CMD} watch --debug-output http --remote-ports 443 2>&1 | tee "${GOTLS_CLIENT_LNAME}" &
    wait

    cat "${GOTLS_CLIENT_LNAME}"

    # check_time_detail_completed_with_last_lines "${HTTPS_LNAME}" 2
    cat "${GOTLS_CLIENT_LNAME}" | grep "baidu.com"
}

function main() {
    test_gotls_client
}

main
