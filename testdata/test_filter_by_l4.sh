#!/usr/bin/env bash

set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
LNAME_IP="${FILE_PREFIX}_filter_by_remote_ip.log"
LNAME_REMOTE_PORT="${FILE_PREFIX}_filter_by_remote_port.log"
LNAME_LOCAL_PORT="${FILE_PREFIX}_filter_by_local_port.log"

function test_filter_by_remote_ip() {
    remote_ip=$(dig example.com +short)
    timeout 20 ${CMD} watch --debug-output http --remote-ips "$remote_ip" 2>&1  | tee "${LNAME_IP}" &
    sleep 10
    curl http://"$remote_ip" &>/dev/null || true
    wait

    cat "${LNAME_IP}"
    cat "${LNAME_IP}" | grep $remote_ip
}


function test_filter_by_remote_port() {
    remote_port=88
    timeout 20 ${CMD} watch --debug-output http --remote-ports "$remote_port" 2>&1  | tee "${LNAME_REMOTE_PORT}" &
    sleep 10
    curl http://example.com &>/dev/null || true
    wait

    cat "${LNAME_REMOTE_PORT}"
    if cat "${LNAME_REMOTE_PORT}" |  grep  "example.com"; then
        exit 1
    fi

    remote_port=80
    timeout 20 ${CMD} watch --debug-output http --remote-ports "$remote_port" 2>&1  | tee "${LNAME_REMOTE_PORT}" &
    sleep 10
    curl http://example.com &>/dev/null || true
    wait

    cat "${LNAME_REMOTE_PORT}"
    if ! cat "${LNAME_REMOTE_PORT}" |  grep  "example.com"; then
        exit 1
    fi
}

function test_filter_by_local_port() {
    local_port=8080
    timeout 20 python3 -m http.server "$local_port" &
    timeout 30 ${CMD} watch --debug-output http --local-ports "$local_port" 2>&1  | tee "${LNAME_LOCAL_PORT}" &
    sleep 10
    curl http://127.0.0.1:"$local_port" &>/dev/null || true
    curl http://127.0.0.1:"$local_port" &>/dev/null || true
    curl http://127.0.0.1:"$local_port" &>/dev/null || true
    wait

    cat "${LNAME_LOCAL_PORT}"
    cat "${LNAME_LOCAL_PORT}" | grep "SimpleHTTP"
}

function main() {
    test_filter_by_remote_ip
    test_filter_by_remote_port
    test_filter_by_local_port
}

main
