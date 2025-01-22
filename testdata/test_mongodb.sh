#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="./mongodbtest/kyanos"
CLIENT_LNAME="${FILE_PREFIX}_mongodb_client.log"
SERVER_LNAME="${FILE_PREFIX}_mongodb_server.log"

function test_mongodb_client() {
    if [ -z "$DOCKER_REGISTRY" ]; then
        IMAGE_NAME="mongo:4.4.15"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/mongo:4.4.15"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-mongo'
    docker rm -f $cname
    cid1=$(docker run -itd --name $cname -p 27017:27017 "$IMAGE_NAME")
    export cid1
    echo $cid1

    sudo timeout 30 ${CMD} watch --debug-output mongodb --remote-ports 27017 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 10
    mongo --eval "db.test.insert({name: 'test', value: 1}); db.test.find({name: 'test'})"
    wait

    cat "${CLIENT_LNAME}"
    docker rm -f $cid1 || true
    check_patterns_in_file "${CLIENT_LNAME}" "insert"
}

function test_mongodb_server() {
    if [ -z "$DOCKER_REGISTRY" ]; then
        IMAGE_NAME="mongo:4.4.15"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/mongo:4.4.15"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-mongo'
    docker rm -f $cname
    cid1=$(docker run -itd --name $cname -p 27017:27017 "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output mongodb --local-ports 27017 2>&1 | tee "${SERVER_LNAME}" &
    sleep 10
    mongo --eval "db.test.insert({name: 'test', value: 1}); db.test.find({name: 'test'})"
    wait

    cat "${SERVER_LNAME}"
    docker rm -f $cid1 || true
    check_patterns_in_file "${SERVER_LNAME}" "insert"
}

function main() {
    mkdir mongodbtest
    test_mongodb_client
    test_mongodb_server
    rm -rf ./mongodbtest
}

main