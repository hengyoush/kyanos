#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
CLIENT_LNAME="${FILE_PREFIX}_redis_client.log"
SERVER_LNAME="${FILE_PREFIX}_redis_server.log"

function test_redis_client() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="redis:7.0.14"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/redis:7.0.14"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-redis'
    docker rm -f $cname
    cid1=$(docker run --name $cname  -p 6379:6379 -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output redis --remote-ports 6379 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 10
    redis-cli -r 5 -i 0.3 hget a key
    wait

    cat "${CLIENT_LNAME}"
    docker rm -f $cid1 || true
    # check_time_detail_completed_with_last_lines "${LNAME}" 3
    check_patterns_in_file "${CLIENT_LNAME}" "HGET"
}


function test_redis_server() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="redis:7.0.14"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/redis:7.0.14"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-redis'
    docker rm -f $cname
    cid1=$(docker run --name $cname  -p 6379:6379 -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output redis --local-ports 6379 2>&1 | tee "${SERVER_LNAME}" &
    sleep 10
    redis-cli -r 50 -i 0.3 hget a key
    wait

    cat "${SERVER_LNAME}"
    docker rm -f $cid1 || true
    # check_time_detail_completed_with_last_lines "${LNAME}" 3
    check_patterns_in_file "${SERVER_LNAME}" "HGET"
}


function main() {
    test_redis_client
    test_redis_server
}

main
