#!/bin/bash
cd bpf && OUTPUT="../.output/" VMLINUX="../vmlinux/x86/vmlinux.h" go generate -v 
cd ..
export CGO_LDFLAGS="-Xlinker -rpath=. -static"  &&  go build
echo "success!"