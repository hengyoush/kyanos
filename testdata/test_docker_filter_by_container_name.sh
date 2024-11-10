#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_docker_filter_by_container_name.log"

function test_docker_filter_by_container_name() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="busybox:1"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/busybox:1"
    fi
    docker pull "$IMAGE_NAME"

    cname='test-kyanos'
    cid1=$(docker run --rm -it --name $cname -d "$IMAGE_NAME" sh -c 'sleep 10; wget -T 10 http://www.baidu.com')
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output http --container-name=${cname} 2>&1 | tee "${LNAME}" &
    sleep 10
    wait

    cat "${LNAME}"
    check_patterns_in_file "${LNAME}" "baidu.com"
}

function main() {
    test_docker_filter_by_container_name
}

main
