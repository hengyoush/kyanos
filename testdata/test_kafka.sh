#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
DOCKER_REGISTRY="$2"
FILE_PREFIX="/tmp/kyanos"
CLIENT_LNAME="${FILE_PREFIX}_kafka_client.log"
SERVER_LNAME="${FILE_PREFIX}_kafka_server.log"


function test_kafka_client() {
    rm -rf /tm/kyanos_kafka_client.log
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="apache/kafka:3.9.0"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/apache/kafka:3.9.0"
    fi

    docker pull ${IMAGE_NAME}
    KAFKA_PORT=9092
    cid=$(docker run -d -p ${KAFKA_PORT}:${KAFKA_PORT} ${IMAGE_NAME})
    sleep 20
    docker exec  $cid bash -c "/opt/kafka/bin/kafka-topics.sh --create --topic quickstart-events --bootstrap-server localhost:${KAFKA_PORT}"
    timeout 30 ${CMD} watch --debug-output kafka --remote-ports ${KAFKA_PORT} 2>&1 | tee "${CLIENT_LNAME}" &
    echo "Sending test messages..."
    sleep 10
    docker exec  $cid bash -c "cat /opt/kafka/bin/kafka-console-producer.sh | /opt/kafka/bin/kafka-console-producer.sh --topic quickstart-events --bootstrap-server localhost:${KAFKA_PORT}"
    sleep 5
    docker rm -f $cid || true
    wait
    cat "${CLIENT_LNAME}"

    cat "${CLIENT_LNAME}" | grep '[request]' | grep  'Apikey:' | grep 'Foundation'
}


function test_kafka_server() {
    rm -rf ${SERVER_LNAME}
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="apache/kafka:3.9.0"
    else
        IMAGE_NAME=$DOCKER_REGISTRY"/apache/kafka:3.9.0"
    fi

    docker pull ${IMAGE_NAME}
    KAFKA_PORT=9092
    cid=$(docker run -d -p ${KAFKA_PORT}:${KAFKA_PORT} ${IMAGE_NAME})
    sleep 20
    docker exec $cid bash -c "/opt/kafka/bin/kafka-topics.sh --create --topic quickstart-events --bootstrap-server localhost:${KAFKA_PORT}"
    timeout 30 ${CMD} watch --debug-output kafka --local-ports ${KAFKA_PORT} 2>&1 | tee "${SERVER_LNAME}" &
    echo "Sending test messages..."
    sleep 10
    docker exec $cid bash -c "cat /opt/kafka/bin/kafka-console-producer.sh | /opt/kafka/bin/kafka-console-producer.sh --topic quickstart-events --bootstrap-server localhost:${KAFKA_PORT}"
    sleep 5
    docker rm -f $cid || true
    wait
    cat "${SERVER_LNAME}"

    cat "${SERVER_LNAME}" | grep '[request]' | grep  'Apikey:' | grep 'Foundation'
}

function main() {
    test_kafka_server
    test_kafka_client
}

main