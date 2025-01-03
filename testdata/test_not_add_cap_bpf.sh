#!/usr/bin/env sh
set -ex

CMD="$1"
FILE_PREFIX="/tmp/kyanos"
LNAME="${FILE_PREFIX}_test_not_add_cap_bpf_before.log"

timeout 30 ${CMD} watch http --debug-output 2>&1 | tee "${LNAME}" &
wait

cat "${LNAME}"
cat "${LNAME}" | grep "requires CAP_BPF"
