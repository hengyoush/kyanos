#!/bin/bash
set -ex
# 创建两个网络命名空间
ip netns add ns1
ip netns add ns2
# 创建两对 veth pair ，一端各挂在一个命名空间下
ip link add v1 type veth peer name v1_p
ip link add v2 type veth peer name v2_p

ip link set v1 netns ns1
ip link set v2 netns ns2
# 分别配置地址，并启用
ip addr add 10.10.10.1/24 dev v1_p
ip link set v1_p up
ip addr add 10.10.20.1/24 dev v2_p
ip link set v2_p up

ip netns exec ns1 ip addr add 10.10.10.2/24 dev v1
ip netns exec ns1 ip link set v1 up
ip netns exec ns2 ip addr add 10.10.20.2/24 dev v2
ip netns exec ns2 ip link set v2 up

# 分别配置路由
ip netns exec ns1 route add -net 10.10.20.0/24 gw 10.10.10.1
ip netns exec ns2 route add -net 10.10.10.0/24 gw 10.10.20.1

# 创建 tun设备，并设置为ipip隧道
# ip netns exec ns1 ip tunnel add tun1 mode ipip remote 10.10.20.2 local 10.10.10.2
# ip netns exec ns1 ip link set tun1 up
# ip netns exec ns1 ip addr add 10.10.100.10 peer 10.10.200.10 dev tun1

# ip netns exec ns2 ip tunnel add tun2 mode ipip remote 10.10.10.2 local 10.10.20.2
# ip netns exec ns2 ip link set tun2 up
# ip netns exec ns2 ip addr add 10.10.200.10 peer 10.10.100.10 dev tun2