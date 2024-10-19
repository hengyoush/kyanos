#!/bin/bash
cd bpf && TARGET=$1 go generate -v 
cd ..
export CGO_LDFLAGS="-Xlinker -rpath=. -static"  &&  go build
echo "success!"