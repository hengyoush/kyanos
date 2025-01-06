#!/usr/bin/env bash

release_num=$(lsb_release -r --short)
if [ $? -ne 0 ]; then
  echo "command not found, supported ubuntu only."
  exit
fi

CLANG_NUM=-12
# shellcheck disable=SC2209
if [ ${release_num} == "20.10" ]; then
  CLANG_NUM=-10
  elif [ ${release_num} == "21.04" ]; then
  CLANG_NUM=-11
  elif [ ${release_num} == "21.10" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "22.04" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "22.10" ]; then
  CLANG_NUM=-12
  elif [ ${release_num} == "23.04" ];then
  CLANG_NUM=-15
  elif [ ${release_num} == "23.10" ];then
    CLANG_NUM=-15
  elif [ ${release_num} == "24.04" ];then
  CLANG_NUM=-18
  else
    echo "used default CLANG Version"
    CLANG_NUM=
fi

echo "CLANG_NUM=${CLANG_NUM}"

UNAME_M=$(uname -m)
ARCH="amd64"
CROSS_ARCH_PATH="arm64"
CROSS_COMPILE=aarch64-linux-gnu-
CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
if [[ ${UNAME_M} =~ "x86_64" ]];then
  ARCH="amd64"
  CROSS_ARCH_PATH="arm64"
  CROSS_COMPILE=aarch64-linux-gnu-
  CROSS_COMPILE_DEB=gcc-aarch64-linux-gnu
  elif [[ ${UNAME_M} =~ "aarch64" ]]; then
    ARCH="arm64"
    CROSS_ARCH_PATH="x86"
    CROSS_COMPILE=x86_64-linux-gnu-
    CROSS_COMPILE_DEB=gcc-x86-64-linux-gnu
    # 在ubuntu 24.04 上， 跨平台的GCC编译器的包名为“gcc-x86-64-linux-gnu”，不是以前的“x86_64-linux-gnu-gcc”
  else
    echo "unsupported arch ${UNAME_M}";
fi

uname -a
sudo apt-get update
sudo apt-get install --yes build-essential pkgconf libelf-dev llvm${CLANG_NUM} clang${CLANG_NUM} linux-tools-common linux-tools-generic ${CROSS_COMPILE_DEB} libssl-dev flex bison bc rsync

for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool${CLANG_NUM} /usr/bin/$tool
done

GOBIN_ZIP="go1.23.3.linux-${ARCH}.tar.gz"
echo "GOBIN_ZIP:${GOBIN_ZIP}"
# install golang
wget https://golang.google.cn/dl/${GOBIN_ZIP}
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf ${GOBIN_ZIP}
export PATH=/usr/local/go/bin:$PATH
export GOPROXY=https://goproxy.cn

cd ~ || exit
git clone https://github.com/hengyoush/kyanos.git
cd kyanos || exit
git submodule update --init --recursive
