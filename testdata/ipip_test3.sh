#!/bin/bash
set -ex
# -- A
ip link add name mybr0 type bridge
ip addr add 10.42.1.1/24 dev mybr0
ip link set dev mybr0 up

ip tunnel add tunl1 mode ipip remote 10.0.4.2 local 10.0.4.9
ip addr add 10.42.1.1/24 dev tunl1
ip link set tunl1 up

# 为了保证我们通过创建的 IPIP 隧道来访问两个不同主机上的子网，我们需要手动添加如下静态路由
ip route add 10.42.2.0/24 dev tunl1

# -- B
ip link add name mybr0 type bridge
ip addr add 10.42.2.1/24 dev mybr0
ip link set dev mybr0 up

ip tunnel add tunl1 mode ipip remote 10.0.4.9 local 10.0.4.2
ip addr add 10.42.2.1/24 dev tunl1
ip link set tunl1 up

ip route add 10.42.1.0/24 dev tunl1