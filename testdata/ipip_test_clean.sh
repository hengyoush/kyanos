#!/bin/bash
set -ex

ip netns del host1
ip netns del host2
ip netns del internet