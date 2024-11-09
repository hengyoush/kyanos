#!/usr/bin/env bash
. $(dirname "$0")/common.sh
set -ex

CMD="$1"
TEST_YAML="$2"
DOCKER_REGISTRY="$3"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_k8s.log"

function test() {
    if [ -z "$DOCKER_REGISTRY" ]; then 
        IMAGE_NAME="alpine:3.18"
    else
        ESCAPED_DOCKER_REGISTRY=$(echo "$DOCKER_REGISTRY" | sed 's/[]\/$*.^|[]/\\&/g')
        IMAGE_NAME=$ESCAPED_DOCKER_REGISTRY"library\/alpine:3.18"
    fi
    sleep 30
    NEW_TEST_YAML="test_k8s_real.yaml"
    sed -e 's/\$IMAGE_NAME/'$IMAGE_NAME'/g' "$TEST_YAML" > $NEW_TEST_YAML
    cat $NEW_TEST_YAML
    kubectl delete -f "${NEW_TEST_YAML}" || true
    kubectl apply -f "${NEW_TEST_YAML}" 
    kubectl wait --for condition=Ready pod/test-kyanos
    kubectl wait --for condition=Ready=False --timeout=20s pod/test-kyanos
    chmod a+x /kyanos
    timeout 20 ${CMD} watch --debug-output http --pod-name test-kyanos  2>&1 | tee "${LNAME}" &
    wait

    cat "${LNAME}"
    cat "${LNAME}" | grep "baidu.com"
}

function main() {
    test
}

main
