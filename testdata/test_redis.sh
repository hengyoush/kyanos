#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_redis.log"

function test_redis() {
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

    timeout 30 ${CMD} watch --debug-output redis --remote-ports 6379 2>&1 | tee "${LNAME}" &
    sleep 10
    redis-cli -r 5 hget a key
    wait

    cat "${LNAME}"
    docker rm -f $cid1 || true
    # check_time_detail_completed_with_last_lines "${LNAME}" 3
    check_patterns_in_file_with_last_lines "${LNAME}" "HGET" 3
}

function main() {
    test_redis
}

main
