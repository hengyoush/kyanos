#!/bin/bash
echo "$1"
echo "$2"
echo "------------------------"
if [ -n "$2" ]
then
    cd bpf && CFLAGS="$1 $2 -I../.output/" OUTPUT="../.output/" go generate -v 
else
    cd bpf && CFLAGS="$1 -I../.output/" OUTPUT="../.output/"  go generate -v 
fi
cd ..
export CGO_LDFLAGS="-Xlinker -rpath=. -static"  &&  go build
echo "success!" 