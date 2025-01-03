#!/usr/bin/env bash
set -ex

DOCKER_REGISTRY="$1"
if [ -n "$DOCKER_REGISTRY" ]; then
  # 检查是否以 / 结尾
  if [[ "$DOCKER_REGISTRY" != */ ]]; then
    DOCKER_REGISTRY="${DOCKER_REGISTRY}/"
  fi
else
  echo "DOCKER_REGISTRY is missing."
fi

sudo docker run -d --cap-add CAP_BPF --name alpine $DOCKER_REGISTRY'alpine' sh -c 'sleep 120' || true
sudo docker cp /host/kyanos/kyanos alpine:/
sudo docker cp ./testdata/test_add_cap_bpf.sh alpine:/
sudo docker exec alpine sh -c 'sh /test_add_cap_bpf.sh "/kyanos"'
sudo docker stop alpine && sudo docker rm alpine

sudo docker run -d --name alpine $DOCKER_REGISTRY'alpine' sh -c 'sleep 120' || true
sudo docker cp /host/kyanos/kyanos alpine:/
sudo docker cp ./testdata/test_not_add_cap_bpf.sh alpine:/
sudo docker exec alpine sh -c 'sh /test_not_add_cap_bpf.sh "/kyanos"'
sudo docker stop alpine && sudo docker rm alpine
