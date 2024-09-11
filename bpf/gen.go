package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type sock_key -type control_value_index_t -type kern_evt -type kern_evt_data -type conn_evt_t -type conn_type_t -type conn_info_t -type endpoint_role_t -type traffic_direction_t -type traffic_protocol_t -type step_t -target amd64 Agent ./pktlatency.bpf.c -- -I./ -I$OUTPUT -I../libbpf/include/uapi -I../vmlinux/x86/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type sock_key -type control_value_index_t -type kern_evt -type kern_evt_data -type conn_evt_t -type conn_type_t -type conn_info_t -type endpoint_role_t -type traffic_direction_t -type traffic_protocol_t -type step_t -cflags "-D KERNEL_VERSION_BELOW_58" -target amd64 AgentOld ./pktlatency.bpf.c -- -I./ -I$OUTPUT -I../libbpf/include/uapi -I../vmlinux/x86/
