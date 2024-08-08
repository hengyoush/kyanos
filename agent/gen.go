package agent

// //go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type  kern_evt -type kern_evt_data -type conn_evt_t -type conn_type_t -type endpoint_role_t -type traffic_direction_t -type traffic_protocol_t -target amd64 agent ../pktlatency.bpf.c -- -I./ -I$OUTPUT -I../libbpf/include/uapi -I../vmlinux/x86/
