#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_mysql.log"

function test_mysql() {
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
    pip install mysql-connector-python || true

    cname='test-mysql'
    docker rm -f $cname || true
    cid1=$(docker run --name $cname -e MYSQL_ROOT_PASSWORD=123456  -p 3306:3306 -v /opt/docker_v/mysql/conf:/etc/mysql/conf.d -d "$IMAGE_NAME")
    export cid1
    echo $cid1

    timeout 30 ${CMD} watch --debug-output mysql --remote-ports 3306 2>&1 | tee "${LNAME}" &
    sleep 10
    python3 ./testdata/query_mysql.py
    wait

    cat "${LNAME}"
    docker rm -f $cid1 || true
    cat "${LNAME}" | grep 'SELECT' | grep  'rows = 1'
    # check_time_detail_completed_with_last_lines "${LNAME}" 1
    # check_patterns_in_file_with_last_lines "${LNAME}" "Resultset rows = 1" 1
}

function main() {
    test_mysql
}

main
