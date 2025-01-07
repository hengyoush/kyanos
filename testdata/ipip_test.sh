#!/bin/bash

# Enable IPIP module
modprobe ipip

# Create the namespaces
ip netns add host1
ip netns add host2
ip netns add internet

# Create the topology
ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

ip link set veth0 netns host1
ip link set veth1 netns internet
ip link set veth2 netns internet
ip link set veth3 netns host2

ip netns exec host1 ip addr add 172.16.10.2/24 dev veth0
ip netns exec host1 ip link set veth0 up
ip netns exec host1 ip link set lo up

ip netns exec host2 ip addr add 152.16.10.2/24 dev veth3
ip netns exec host2 ip link set veth3 up
ip netns exec host2 ip link set lo up

ip netns exec internet ip addr add 172.16.10.1/24 dev veth1
ip netns exec internet ip link set veth1 up
ip netns exec internet ip addr add 152.16.10.1/24 dev veth2
ip netns exec internet ip link set veth2 up
ip netns exec internet ip link set lo up
ip netns exec internet sysctl -w net.ipv4.ip_forward=1

# Create gre tunnel on host1
ip netns exec host1 ip tunnel add tun0 mode ipip local 172.16.10.2 remote 152.16.10.2 ttl 255
ip netns exec host1 ip addr add 192.168.50.1/30 dev tun0
ip netns exec host1 ip link set tun0 up

# Create gre tunnel on host2
ip netns exec host2 ip tunnel add tun0 mode ipip local 152.16.10.2 remote 172.16.10.2 ttl 255
ip netns exec host2 ip addr add 192.168.50.2/30 dev tun0
ip netns exec host2 ip link set tun0 up

# Add static route
ip netns exec host1 route add -net 152.16.10.0/24 gw 172.16.10.1
ip netns exec host2 route add -net 172.16.10.0/24 gw 152.16.10.1

echo "Setup done."