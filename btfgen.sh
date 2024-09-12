#!/bin/bash
current_dir=$(pwd)
rm -rf ./bpf/custom-archive
cd ../btfhub || exit
make bring
./tools/btfgen.sh -a x86_64 -o "$current_dir"/bpf/agent_x86_bpfel.o
cd "$current_dir" || exit
cp -R ../btfhub/custom-archive ./bpf/