package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-D ARCH_$TARGET" -type in6_addr -type process_exit_event -type process_exec_event -type kern_evt_ssl_data -type conn_id_s_t -type sock_key -type control_value_index_t -type kern_evt -type kern_evt_data -type conn_evt_t -type conn_type_t -type conn_info_t -type endpoint_role_t -type traffic_direction_t -type traffic_protocol_t -type step_t -target $TARGET Agent ./pktlatency.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cflags "-D LAGACY_KERNEL_310 -D ARCH_$TARGET"  -target $TARGET AgentLagacyKernel310 ./pktlatency.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl102a ./openssl_1_0_2a.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl110a ./openssl_1_1_0a.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl111a ./openssl_1_1_1a.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl111b ./openssl_1_1_1b.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl111d ./openssl_1_1_1d.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl111j ./openssl_1_1_1j.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl300 ./openssl_3_0_0.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl310 ./openssl_3_1_0.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl320 ./openssl_3_2_0.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl323 ./openssl_3_2_3.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET Openssl330 ./openssl_3_3_0.bpf.c -- -I./ -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET/
