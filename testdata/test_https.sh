#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTPS_CLIENT_LNAME="${FILE_PREFIX}_https_client.log"
HTTPS_SERVER_LNAME="${FILE_PREFIX}_https_server.log"
SENDFILE_TEST_LNAME="${FILE_PREFIX}_sendfile_test.log"
NGINX_SERVER_HTTPS_TEST_LNAME="${FILE_PREFIX}_nginx_server_http_test.log"

function test_http_plain_client() {
    pip install --break-system-packages requests || true
    timeout 30 python3 ./testdata/request_https.py 60 'https://httpbin.org/headers' &
    echo "after python3 exec"
    date
    sleep 10
    echo "after sleep 10s"
    date
    timeout 30 ${CMD} watch --debug-output http --remote-ports 443 2>&1 | tee "${HTTPS_CLIENT_LNAME}" &
    wait

    cat "${HTTPS_CLIENT_LNAME}"

    # check_time_detail_completed_with_last_lines "${HTTPS_LNAME}" 2
    cat "${HTTPS_CLIENT_LNAME}" | grep "httpbin"
}

function test_http_plain_server() {
    openssl req -x509 -newkey rsa:2048 -keyout server.pem -out server.pem -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost"

    pip install --break-system-packages ssl || true
    timeout 40 python3 ./testdata/start_https_server.py  &
    timeout 30 python3 ./testdata/request_https.py 60 'https://localhost:4443' &
    sleep 10
    timeout 30 ${CMD} watch --debug-output http --local-ports 4443 2>&1 | tee "${HTTPS_SERVER_LNAME}" &
    wait

    cat "${HTTPS_SERVER_LNAME}"

    # check_time_detail_completed_with_last_lines "${HTTPS_LNAME}" 2
    cat "${HTTPS_SERVER_LNAME}" | grep "python-requests"
}

function test_https_nginx_server() {
    TEST_DIR=/etc/test
    rm -rf ${TEST_DIR:?}/*
    mkdir -p ${TEST_DIR}
    openssl genrsa -out ${TEST_DIR}/nginx.key 2048
    openssl req -new -x509 -key ${TEST_DIR}/nginx.key -out ${TEST_DIR}/nginx.crt -days 365 -nodes -subj "/C=US/ST=California/L=San Francisco/O=My Company/CN=localhost"
    chmod -R a+r ${TEST_DIR}/*
    # start ngnix https server via docker
    cid=$(docker run --rm -d -p 1443:1443 -v ./testdata/nginx_https.conf:/etc/nginx/nginx.conf:ro -v ${TEST_DIR}:${TEST_DIR} nginx:latest)
    export cid
    echo $cid
    timeout 30 ${CMD} watch --debug-output http --local-ports 1443 2>&1 | tee "${NGINX_SERVER_HTTPS_TEST_LNAME}" &
    sleep 20
    
    curl -k https://localhost:1443 || true
    sleep 3
    docker stop $cid
    wait
    cat "${NGINX_SERVER_HTTPS_TEST_LNAME}"
    check_patterns_in_file "${NGINX_SERVER_HTTPS_TEST_LNAME}" "[request]"
}


function test_sendfile() {
    # start ngnix https server via docker
    cid=$(docker run --rm -d -p 1880:80  nginx:latest)
    export cid
    echo $cid
    timeout 30 ${CMD} watch --debug-output http --local-ports 80 2>&1 | tee "${SENDFILE_TEST_LNAME}" &
    sleep 20
    
    curl  http://localhost:1880 || true
    sleep 3
    docker stop $cid
    wait
    cat "${SENDFILE_TEST_LNAME}"
    check_patterns_in_file "${SENDFILE_TEST_LNAME}" "[request]"
}

function main() {
    test_http_plain_client
    test_http_plain_server
    test_https_nginx_server
    test_sendfile
}

main
