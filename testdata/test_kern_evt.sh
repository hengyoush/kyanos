#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTP_PLAIN_CLIENT_LNAME="${FILE_PREFIX}_http_plain_client.log"

function test_http_plain_client() {
    timeout 20 ${CMD} watch --debug-output http 2>&1 | tee "${HTTP_PLAIN_CLIENT_LNAME}" &
    sleep 10
    curl http://www.baidu.com &>/dev/null || true
    wait

    cat "${HTTP_PLAIN_CLIENT_LNAME}"
    check_time_detail_completed "${HTTP_PLAIN_CLIENT_LNAME}"
}

function main() {
    test_http_plain_client
}

main
