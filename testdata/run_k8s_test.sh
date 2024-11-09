#!/usr/bin/env bash

set -ex

DOCKER_REGISTRY="$1"
INSTALL_KIND="$2"

if [ -n "$DOCKER_REGISTRY" ]; then
  # 检查是否以 / 结尾
  if [[ "$DOCKER_REGISTRY" != */ ]]; then
    DOCKER_REGISTRY="${DOCKER_REGISTRY}/"
  fi
else
  echo "DOCKER_REGISTRY is missing."
fi

if [ -n "$INSTALL_KIND" ]; then 
    wget https://github.com/kubernetes-sigs/kind/releases/download/v0.23.0/kind-linux-amd64
    chmod a+x kind-linux-amd64
    sudo cp ./kind-linux-amd64 /usr/local/bin/kind
fi

# 拉取kind镜像
docker pull $DOCKER_REGISTRY'kindest/node:v1.27.3' || true
# kind启动集群
kind delete cluster || true
kind create cluster --image $DOCKER_REGISTRY'kindest/node:v1.27.3' || true
# 加载alpine镜像到kind集群里
docker pull $DOCKER_REGISTRY'alpine:3.18' || true
kind load docker-image $DOCKER_REGISTRY'alpine:3.18' || true
# 启动测试脚本
sudo docker cp /host/kyanos/kyanos kind-control-plane:/
sudo docker cp ./testdata/test_k8s.yaml kind-control-plane:/
sudo docker cp ./testdata/test_k8s.sh kind-control-plane:/
sudo docker exec kind-control-plane sh -c  'bash /test_k8s.sh /kyanos /test_k8s.yaml '$DOCKER_REGISTRY
kind delete cluster || true