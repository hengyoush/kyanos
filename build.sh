#!/bin/bash
cd agent && OUTPUT="../.output/" VMLINUX="../vmlinux/x86/vmlinux.h" go generate -v 
cd ..
cd bpf && OUTPUT="../.output/" VMLINUX="../vmlinux/x86/vmlinux.h" go generate -v 
cd ..
go build
echo "success!"