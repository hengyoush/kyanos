#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
ROCKETMQ_CLIENT_LNAME="${FILE_PREFIX}_rocketmq_client.log"
ROCKETMQ_SERVER_LNAME="${FILE_PREFIX}_rocketmq_server.log"

function test_rocketmq() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="apache/rocketmq:5.3.1"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/apache/rocketmq:5.3.1"
    fi

    docker-compose up -d

    timeout 30 ${CMD} watch --debug-output rocketmq --remote-ports 9876,8080 2>&1 | tee "${ROCKETMQ_CLIENT_LNAME}" &
    sleep 10

    python3 test_rocketmq.py
    python3 test_rocketmq.py consume &
    sleep 10
    pkill -f test_rocketmq.py

    wait

    cat "${ROCKETMQ_CLIENT_LNAME}"
    docker rm -f rmqnamesrv rmqbroker || true
    check_patterns_in_file "${ROCKETMQ_CLIENT_LNAME}" "Hello RocketMQ"
}

function main() {
    test_rocketmq
}

main
