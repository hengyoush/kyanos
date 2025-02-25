#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
CLIENT_LNAME="${FILE_PREFIX}_ipv6_client.log"


function test_client() {
    # client start after kyanos
    timeout 30 ${CMD} watch --debug-output http --comm curl --trace-ssl-event=false 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 15
    curl -6 'http://ipv6.baidu.com'  &>/dev/null || true
    wait

    cat "${CLIENT_LNAME}"
    cat "${CLIENT_LNAME}" | grep "Host: ipv6.baidu.com"
}

function main() {
    test_client
}

main