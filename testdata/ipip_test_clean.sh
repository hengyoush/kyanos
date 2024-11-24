#!/bin/bash
set -ex


ip link del v1_p
ip link del v2_p
ip netns del ns1
ip netns del ns2