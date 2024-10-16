#!/usr/bin/env bash

set -ex

DOCKER_REGISTRY=$1

function main() {
  rm -rf /tmp/kyanos_* | true
  # kubectl delete pod test-ptcpdump | true

  bash testdata/test_base.sh ./kyanos
  bash testdata/test_filter_by_l4.sh ./kyanos
  bash testdata/test_kern_evt.sh ./kyanos
  bash testdata/test_docker_filter_by_container_id.sh ./kyanos "$DOCKER_REGISTRY"
  bash testdata/test_docker_filter_by_container_name.sh ./kyanos "$DOCKER_REGISTRY"
  bash testdata/test_docker_filter_by_pid.sh ./kyanos
  bash testdata/test_containerd_filter_by_container_id.sh ./kyanos "$DOCKER_REGISTRY"
  bash testdata/test_containerd_filter_by_container_name.sh ./kyanos "$DOCKER_REGISTRY"
  echo "success!"
}

main
