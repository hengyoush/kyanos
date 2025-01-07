#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_rocketmq_client.log"
DOCKER_COMPOSE_FILE="/tmp/docker-compose-rocketmq.yml"

function create_docker_compose_file() {
    cat <<EOF > "$DOCKER_COMPOSE_FILE"
version: '3.8'
services:
  namesrv:
    image: ${DOCKER_REGISTRY:-apache/rocketmq:5.3.1}
    container_name: rmqnamesrv
    ports:
      - 9876:9876
    networks:
      - rocketmq
    command: sh mqnamesrv
  broker:
    image: ${DOCKER_REGISTRY:-apache/rocketmq:5.3.1}
    container_name: rmqbroker
    ports:
      - 10909:10909
      - 10911:10911
      - 10912:10912
    environment:
      - NAMESRV_ADDR=rmqnamesrv:9876
    depends_on:
      - namesrv
    networks:
      - rocketmq
    command: sh mqbroker
  proxy:
    image: ${DOCKER_REGISTRY:-apache/rocketmq:5.3.1}
    container_name: rmqproxy
    networks:
      - rocketmq
    depends_on:
      - broker
      - namesrv
    ports:
      - 8080:8080
      - 8081:8081
    restart: on-failure
    environment:
      - NAMESRV_ADDR=rmqnamesrv:9876
    command: sh mqproxy
networks:
  rocketmq:
    driver: bridge
EOF
}

function test_rocketmq() {
    pip --break-system-packages install rocketmq 

    create_docker_compose_file

    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    sleep 20

    timeout 30 ${CMD} watch --debug-output rocketmq --remote-ports 9876 2>&1 | tee "${LNAME}" &
    sleep 10

    echo "Sending test messages..."
    python3 ./testdata/rocketmq_producer.py
    wait
    sleep 2

    cat "${LNAME}"
    docker-compose -f "$DOCKER_COMPOSE_FILE" down
    rm -f "$DOCKER_COMPOSE_FILE"

    check_patterns_in_file "${LNAME}" "TestTopic"
}

function main() {
    test_rocketmq
}

main