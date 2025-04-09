#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_dns.log"

function test_dns() {
    timeout 20 ${CMD} watch dns --debug-output 2>&1 | tee "${LNAME}" &
    sleep 10
    dig example.com &>/dev/null || true
    wait

    cat "${LNAME}"
    cat "${LNAME}" | grep 'example.com'
}

function main() {
    test_dns
}

main
