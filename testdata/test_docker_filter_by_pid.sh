#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_docker_filter_by_pid.log"

function test_docker_filter_by_pid() {

    timeout 20 ${CMD} watch --debug-output http --pids $$ 2>&1 | tee "${LNAME}" &
    sleep 10
    curl http://www.baidu.com &>/dev/null || true
    wait

    cat "${LNAME}"
    check_time_detail_completed "${LNAME}"
    check_patterns_in_file "${LNAME}" "baidu.com"
}

function main() {
    test_docker_filter_by_pid
}

main
