#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
CLIENT_MATCH_LNAME="${FILE_PREFIX}_side_client_match.log"
CLIENT_NONMATCH_LNAME="${FILE_PREFIX}_side_client_nonmatch.log"

function test_side_client_match() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="mysql:5.7.19"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/mysql:5.7.19"
    fi
    docker pull "$IMAGE_NAME"
    mkdir -p /opt/docker_v/mysql/conf
    pushd /opt/docker_v/mysql/conf
    touch  my.cnf
    printf "[mysqld]\nskip_ssl" > my.cnf
    popd
    pip install --break-system-packages mysql-connector-python || true

    cname='test-mysql'
    docker rm -f $cname || true
    cid1=$(docker run --name $cname -e MYSQL_ROOT_PASSWORD=123456  -p 3306:3306 -v /opt/docker_v/mysql/conf:/etc/mysql/conf.d -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output mysql --side client 2>&1 | tee "${CLIENT_MATCH_LNAME}" &
    sleep 10
    python3 ./testdata/query_mysql.py 5
    wait

    cat "${CLIENT_MATCH_LNAME}"
    cat "${CLIENT_MATCH_LNAME}" | grep '\[side\]=client'
    check_patterns_not_in_file "${CLIENT_MATCH_LNAME}"  '\[side\]=server'

    docker rm -f $cid1 || true
}

function test_side_client_nonmatch() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="mysql:5.7.19"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/library/mysql:5.7.19"
    fi
    docker pull "$IMAGE_NAME"
    mkdir -p /opt/docker_v/mysql/conf
    pushd /opt/docker_v/mysql/conf
    touch  my.cnf
    printf "[mysqld]\nskip_ssl" > my.cnf
    popd
    pip install --break-system-packages mysql-connector-python || true

    cname='test-mysql'
    docker rm -f $cname || true
    cid1=$(docker run --name $cname -e MYSQL_ROOT_PASSWORD=123456  -p 3306:3306 -v /opt/docker_v/mysql/conf:/etc/mysql/conf.d -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output mysql --side server 2>&1 | tee "${CLIENT_NONMATCH_LNAME}" &
    sleep 10
    python3 ./testdata/query_mysql.py 20
    wait

    cat "${CLIENT_NONMATCH_LNAME}"
    cat "${CLIENT_NONMATCH_LNAME}" | grep '\[side\]=server'
    check_patterns_not_in_file "${CLIENT_NONMATCH_LNAME}"  '\[side\]=client'

    docker rm -f $cid1 || true
}

function main() {
    test_side_client_match
    test_side_client_nonmatch
}

main
