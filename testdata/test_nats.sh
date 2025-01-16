#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
ECHO_LNAME="${FILE_PREFIX}_nats_echo.log"

function test_nats_echo() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="nats:2.10.24"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/nats:2.10.24"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-nats'
    docker rm -f $cname
    cid1=$(docker run --name $cname  -p 4222:4222 -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch nats --debug-output 2>&1 | tee "${ECHO_LNAME}" &
    sleep 2
    ./testdata/nats/nats_echo --echo demo.subject --count 10 --interval 2s &>/dev/null || true
    wait

    cat "${ECHO_LNAME}"
    docker rm -f $cid1 || true
    check_patterns_in_file "${ECHO_LNAME}" "PUB"
}

function main() {
    test_nats_echo
}

main
