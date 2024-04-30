#!/usr/bin/env bash
bpftool map show | grep xaos
bpftool prog show | grep sock
ls /sys/fs/bpf