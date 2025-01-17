#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
CLIENT_LNAME="${FILE_PREFIX}_truncated_client.log"
SERVER_LNAME="${FILE_PREFIX}_truncated_server.log"


function test_client() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="lobehub/lobe-chat:v1.46.7"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/lobehub/lobe-chat:v1.46.7"
    fi
    docker pull "$IMAGE_NAME"

    cname='lobe'
    port=3210
    docker rm -f $cname
    cid1=$(docker run --name $cname  -p $port:$port -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output http --remote-ports $port 2>&1 | tee "${CLIENT_LNAME}" &
    sleep 15
    curl http://localhost:3210
    wait

    cat "${CLIENT_LNAME}"
    docker rm -f $cid1 || true
    check_patterns_in_file "${CLIENT_LNAME}" "localhost:3210"
}


function test_server() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="lobehub/lobe-chat:v1.46.7"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/lobehub/lobe-chat:v1.46.7"
    fi
    docker pull "$IMAGE_NAME"

    cname='lobe'
    port=3210
    docker rm -f $cname
    cid1=$(docker run --name $cname  -p $port:$port -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output http --local-ports $port 2>&1 | tee "${SERVER_LNAME}" &
    sleep 15
    curl http://localhost:3210
    wait

    cat "${SERVER_LNAME}"
    docker rm -f $cid1 || true
    check_patterns_in_file "${SERVER_LNAME}" "localhost:3210"
}


function main() {
    test_client
    test_server
}

main