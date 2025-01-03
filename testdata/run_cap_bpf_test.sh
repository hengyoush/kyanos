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

# CAP_SYS_RESOURCE reference: https://docs.ebpf.io/linux/concepts/resource-limit/
sudo docker run -d --ulimit memlock=100000000000:100000000000 --cap-add=CAP_SYS_RESOURCE --name alpine $DOCKER_REGISTRY'alpine' sh -c 'sleep 120' || true
sudo docker cp /host/kyanos/kyanos alpine:/
sudo docker cp ./testdata/test_not_add_cap_bpf.sh alpine:/
sudo docker cp /var/lib/kyanos/btf/current.btf alpine:/
sudo docker exec alpine sh -c 'sh /test_not_add_cap_bpf.sh "/kyanos --btf /current.btf"'
sudo docker stop alpine && sudo docker rm alpine

# mount sys reference: https://stackoverflow.com/questions/75808955/error-mounting-sys-kernel-debug-tracing-to-rootfs
sudo docker run -d -v /sys/:/sys/ --privileged --name alpine $DOCKER_REGISTRY'alpine' sh -c 'sleep 120' || true
sudo docker cp /host/kyanos/kyanos alpine:/
sudo docker cp ./testdata/test_add_cap_bpf.sh alpine:/
sudo docker cp /var/lib/kyanos/btf/current.btf alpine:/
sudo docker exec alpine sh -c 'sh /test_add_cap_bpf.sh "/kyanos --btf /current.btf"'
sudo docker stop alpine && sudo docker rm alpine
