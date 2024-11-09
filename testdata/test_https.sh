#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
HTTPS_CLIENT_LNAME="${FILE_PREFIX}_https_client.log"
HTTPS_SERVER_LNAME="${FILE_PREFIX}_https_server.log"

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
function main() {
    test_http_plain_client
    test_http_plain_server
}

main
