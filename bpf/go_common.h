// A set of symbols that are useful for various different uprobes.
// Currently, this includes mostly connection related items,
// which applies to any network protocol tracing (HTTP2, TLS, etc.).
struct go_common_symaddrs_t {
  // ---- itable symbols ----

  // net.Conn interface types.
  // go.itab.*google.golang.org/grpc/credentials/internal.syscallConn,net.Conn
  int64_t internal_syscallConn;
  int64_t tls_Conn;     // go.itab.*crypto/tls.Conn,net.Conn
  int64_t net_TCPConn;  // go.itab.*net.TCPConn,net.Conn

  // ---- struct member offsets ----

  // Members of internal/poll.FD.
  int32_t FD_Sysfd_offset;  // 16

  // Members of crypto/tls.Conn.
  int32_t tlsConn_conn_offset;  // 0

  // Members of google.golang.org/grpc/credentials/internal.syscallConn
  int32_t syscallConn_conn_offset;  // 0

  // Member of runtime.g.
  int32_t g_goid_offset;  // 152

  // Offset of the ptr to struct g from the address in %fsbase.
  int32_t g_addr_offset;  // -8
};



struct tgid_goid_t {
  uint32_t tgid;
  int64_t goid;
};

// A map that communicates the location of symbols within a binary.
// This particular map has symbols that are common across golang probes.
// It is used by both go_http2_trace and go_tls_trace, and is thus included globally here.
//   Key: TGID
//   Value: Symbol addresses for the binary with that TGID.
MY_BPF_HASH(go_common_symaddrs_map, uint32_t, struct go_common_symaddrs_t);


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct tgid_goid_t));
	__uint(value_size, sizeof(struct nested_syscall_fd_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} go_ssl_user_space_call_map SEC(".maps");

#if defined(ARCH_amd64)
struct thread_struct___v46 {
	/* Cached TLS descriptors: */
	struct desc_struct	tls_array[3];
	unsigned long		sp0;
	unsigned long		sp;
	unsigned long		usersp;	/* Copy from PDA */
	unsigned short		es;
	unsigned short		ds;
	unsigned short		fsindex;
	unsigned short		gsindex;
	unsigned long		fs;
};
#endif
// Gets the ID of the go routine currently scheduled on the current tgid and pid.
// We do that by accessing the thread local storage (fsbase) of the current pid from the
// task_struct. From the tls, we find a pointer to the g struct and access the goid.
static inline uint64_t get_goid(struct pt_regs* ctx) {
  // return 0;
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  struct go_common_symaddrs_t* common_symaddrs = bpf_map_lookup_elem(&go_common_symaddrs_map, &tgid);
  if (common_symaddrs == NULL) {
    return 0;
  }

  // Get fsbase from `struct task_struct`.
  const struct task_struct* task_ptr = (struct task_struct*)bpf_get_current_task();
  if (!task_ptr) {
    return 0;
  }
  int offsetof_thread = bpf_core_field_offset(task_ptr->thread);
  struct thread_struct *thr = (void*)task_ptr + offsetof_thread;

#if defined(LAGACY_KERNEL_310) && defined(ARCH_amd64)
  const void* fs_base = (void*)BPF_CORE_READ((struct thread_struct___v46 *)thr, fs);
#elif defined(ARCH_amd64)
  const void* fs_base = (void*)_C(thr,fsbase);
#elif defined(ARCH_arm64)
  const void* fs_base = (void*)_C(thr,uw.tp_value);
#else
#error Target architecture not supported
#endif

  // Get ptr to `struct g` from 8 bytes before fsbase and then access the goID.
  uint64_t goid;
  size_t g_addr;
  bpf_probe_read_user(&g_addr, sizeof(void*), (void*)(fs_base + common_symaddrs->g_addr_offset));
  bpf_probe_read_user(&goid, sizeof(void*), (void*)(g_addr + common_symaddrs->g_goid_offset));
  return goid;
}
