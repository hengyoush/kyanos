//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"
#include "data_common.h"
#include "go_common.h"

// Utility macro for use in BPF code, so the probe can exit if the symbol doesn't exist.
#define REQUIRE_SYMADDR(symaddr, retval) \
  if (symaddr == -1) {                   \
    return retval;                       \
  }


#define REQUIRE_LOCATION(loc, retval)     \
  if (loc.type == kLocationTypeInvalid) { \
    return retval;                        \
  }

#define kInvalidFD -1

struct go_interface {
  int64_t type;
  void* ptr;
};

enum location_type_t {
  kLocationTypeInvalid = 0,
  kLocationTypeStack = 1,
  kLocationTypeRegisters = 2
};

struct location_t {
  enum location_type_t type;
  int32_t offset;
};
// Contains the registers of the golang register ABI.

// This struct is required because we use it in the regs_heap BPF map,
// which enables us to allocate this memory on the BPF heap instead of the BPF map.
struct go_regabi_regs {
  uint64_t regs[9];
};

struct go_tls_symaddrs_t {
  // ---- function argument locations ----

  // Arguments of crypto/tls.(*Conn).Write.
  struct location_t Write_c_loc;        // 8
  struct location_t Write_b_loc;        // 16
  struct location_t Write_retval0_loc;  // 40
  struct location_t Write_retval1_loc;  // 48

  // Arguments of crypto/tls.(*Conn).Read.
  struct location_t Read_c_loc;        // 8
  struct location_t Read_b_loc;        // 16
  struct location_t Read_retval0_loc;  // 40
  struct location_t Read_retval1_loc;  // 48
};

struct go_tls_conn_args {
  void* conn_ptr;
  char* plaintext_ptr;
};

const enum location_type_t *location_type_t_unused __attribute__((unused));
const struct location_t *location_t_unused __attribute__((unused));
const struct go_tls_symaddrs_t *go_tls_symaddrs_t_unused __attribute__((unused));
const struct go_common_symaddrs_t *go_common_symaddrs_t_unused __attribute__((unused));

MY_BPF_HASH(go_tls_symaddrs_map, uint32_t, struct go_tls_symaddrs_t);

// Key is tgid + goid (goroutine id).
// Value is a pointer to the argument to the crypto/tls.(*Conn) Write and Read functions.
// This map is used to connect arguments to return values.
MY_BPF_HASH(active_tls_conn_op_map, struct tgid_goid_t, struct go_tls_conn_args);

// The BPF map used to store the registers of Go's register-based calling convention.
MY_BPF_ARRAY_PERCPU(regs_heap, struct go_regabi_regs);


// Copies the registers of the golang ABI, so that they can be
// easily accessed using an offset.
static __inline uint64_t* go_regabi_regs(const struct pt_regs* ctx) {
  uint32_t kZero = 0;
  struct go_regabi_regs* regs_heap_var = bpf_map_lookup_elem(&regs_heap, &kZero);
  if (regs_heap_var == NULL) {
    return NULL;
  }

#if defined(ARCH_amd64)
  regs_heap_var->regs[0] = _C(ctx,ax);
  regs_heap_var->regs[1] = _C(ctx,bx);
  regs_heap_var->regs[2] = _C(ctx,cx);
  regs_heap_var->regs[3] = _C(ctx,di);
  regs_heap_var->regs[4] = _C(ctx,si);
  regs_heap_var->regs[5] = _C(ctx,r8);
  regs_heap_var->regs[6] = _C(ctx,r9);
  regs_heap_var->regs[7] = _C(ctx,r10);
  regs_heap_var->regs[8] = _C(ctx,r11);
#elif defined(ARCH_arm64)
#pragma unroll
  for (uint32_t i = 0; i < 9; i++) {
    regs_heap_var->regs[i] = ctx->regs[i];
  }
#else
#error Target Architecture not supported
#endif

  return regs_heap_var->regs;
}

// Reads a golang function argument, taking into account the ABI.
// Go arguments may be in registers or on the stack.
static __inline void assign_arg(void* arg, size_t arg_size, struct location_t loc, const void* sp,
                                uint64_t* regs) {
  if (loc.type == kLocationTypeStack) {
    bpf_probe_read(arg, arg_size, sp + loc.offset);
  } else if (loc.type == kLocationTypeRegisters) {
    if (loc.offset >= 0) {
      bpf_probe_read(arg, arg_size, (char*)regs + loc.offset);
    }
  }
}


static __inline int32_t get_fd_from_conn_intf_core(struct go_interface conn_intf,
                                                   const struct go_common_symaddrs_t* symaddrs) {
  REQUIRE_SYMADDR(symaddrs->FD_Sysfd_offset, kInvalidFD);

  if (conn_intf.type == symaddrs->internal_syscallConn) {
    REQUIRE_SYMADDR(symaddrs->syscallConn_conn_offset, kInvalidFD);
    const int kSyscallConnConnOffset = 0;
    bpf_probe_read(&conn_intf, sizeof(conn_intf),
                   conn_intf.ptr + symaddrs->syscallConn_conn_offset);
  }

  if (conn_intf.type == symaddrs->tls_Conn) {
    REQUIRE_SYMADDR(symaddrs->tlsConn_conn_offset, kInvalidFD);
    bpf_probe_read(&conn_intf, sizeof(conn_intf), conn_intf.ptr + symaddrs->tlsConn_conn_offset);
  }

  if (conn_intf.type != symaddrs->net_TCPConn) {
    return kInvalidFD;
  }

  void* fd_ptr;
  bpf_probe_read(&fd_ptr, sizeof(fd_ptr), conn_intf.ptr);

  int64_t sysfd;
  bpf_probe_read(&sysfd, sizeof(int64_t), fd_ptr + symaddrs->FD_Sysfd_offset);

  return sysfd;
}

SEC("uprobe/dummy:go_tls_write")
int probe_entry_tls_conn_write(struct pt_regs* ctx) {
  // bpf_printk("probe_entry_tls_conn_write");

  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  struct go_tls_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_tls_symaddrs_map, &tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  // Required argument offsets.
  REQUIRE_LOCATION(symaddrs->Write_c_loc, 0);
  REQUIRE_LOCATION(symaddrs->Write_b_loc, 0);

  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)_C(ctx,sp);
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  struct go_tls_conn_args args = {};
  assign_arg(&args.conn_ptr, sizeof(args.conn_ptr), symaddrs->Write_c_loc, sp, regs);
  assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr), symaddrs->Write_b_loc, sp, regs);

  bpf_map_update_elem(&active_tls_conn_op_map, &tgid_goid, &args, BPF_ANY);

  struct nested_syscall_fd_t nested_syscall_fd = {
      .fd = kInvalidFD,
      .syscall_len = 0,
  };
  bpf_map_update_elem(&go_ssl_user_space_call_map, &tgid_goid, &nested_syscall_fd, BPF_ANY);

  return 0;

}

static __inline int probe_return_tls_conn_write_core(struct pt_regs* ctx, uint64_t id, uint32_t tgid, struct go_tls_conn_args* args, struct tgid_goid_t tgoid) {
struct go_tls_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_tls_symaddrs_map, &tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  REQUIRE_LOCATION(symaddrs->Write_retval0_loc, 0);
  REQUIRE_LOCATION(symaddrs->Write_retval1_loc, 0);

  const void* sp = (const void*)_C(ctx,sp);
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }
  int64_t retval0 = 0;
  assign_arg(&retval0, sizeof(retval0), symaddrs->Write_retval0_loc, sp, regs);

  struct go_interface retval1 = {};
  assign_arg(&retval1, sizeof(retval1), symaddrs->Write_retval1_loc, sp, regs);

  // bpf_printk("probe_return_tls_conn_write_core retval1.ptr: %d, loctype:%d, conn:%d",retval1.ptr , symaddrs->Write_retval1_loc.type, args->conn_ptr);
  // If function returns an error, then there's no data to trace.
  if (retval1.ptr != 0) {
    return 0;
  }
  // bpf_printk("probe_return_tls_conn_write_core retval1!=0");


  struct go_common_symaddrs_t* common_symaddrs = bpf_map_lookup_elem(&go_common_symaddrs_map, &tgid);
  if (common_symaddrs == NULL) {
    return 0;
  }

  // To call get_fd_from_conn_intf, cast the conn_ptr into a go_interface.
  struct go_interface conn_intf;
  conn_intf.type = common_symaddrs->tls_Conn;
  conn_intf.ptr = args->conn_ptr;
  int fd = get_fd_from_conn_intf_core(conn_intf, common_symaddrs);
  if (fd == kInvalidFD) {
    return 0;
  }

  // syscall len
  struct nested_syscall_fd_t* nested_syscall_fd_ptr = bpf_map_lookup_elem(&go_ssl_user_space_call_map, &tgoid);
  if (nested_syscall_fd_ptr == NULL) {
      return 0;
  }

  int fd2 = nested_syscall_fd_ptr->fd;

  struct data_args write_args = {};
  write_args.source_fn = kSSLWrite;
  write_args.buf = args->plaintext_ptr;
  write_args.fd = fd;

  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
  // bpf_printk("gotls, conn_info:%d,bc:%d", conn_info,retval0);
  if (conn_info) {
  // bpf_printk("gotls, conn_info exists");
    conn_info->ssl = true;
    process_syscall_data_with_conn_info(ctx, &write_args, tgid_fd, kEgress, retval0, conn_info, nested_syscall_fd_ptr->syscall_len, true, true);
    
    conn_info->ssl_write_bytes += retval0;
  }
  return 0;
}


SEC("uretprobe/dummy:go_tls_write")
int probe_return_tls_conn_write(struct pt_regs* ctx) {
  // bpf_printk("probe_return_tls_conn_write");

  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  struct go_tls_conn_args* args = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
  if (args == NULL) {
    return 0;
  }

  probe_return_tls_conn_write_core(ctx, id, tgid, args, tgid_goid);

  bpf_map_delete_elem(&active_tls_conn_op_map, &tgid_goid);

  bpf_map_delete_elem(&go_ssl_user_space_call_map, &tgid_goid);

  return 0;

}

SEC("uprobe/dummy:go_tls_read")
int probe_entry_tls_conn_read(struct pt_regs* ctx) {
  // bpf_printk("probe_entry_tls_conn_read");

  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;

  struct go_tls_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_tls_symaddrs_map, &tgid);
  if (symaddrs == NULL) {
    return 0;
  }

  // Required argument offsets.
  REQUIRE_LOCATION(symaddrs->Read_c_loc, 0);
  REQUIRE_LOCATION(symaddrs->Read_b_loc, 0);

  // ---------------------------------------------
  // Extract arguments
  // ---------------------------------------------

  const void* sp = (const void*)_C(ctx,sp);
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }

  struct go_tls_conn_args args = {};
  assign_arg(&args.conn_ptr, sizeof(args.conn_ptr), symaddrs->Read_c_loc, sp, regs);
  assign_arg(&args.plaintext_ptr, sizeof(args.plaintext_ptr), symaddrs->Read_b_loc, sp, regs);

  bpf_map_update_elem(&active_tls_conn_op_map, &tgid_goid, &args, BPF_ANY);


  struct nested_syscall_fd_t nested_syscall_fd = {
      .fd = kInvalidFD,
      .syscall_len = 0,
  };
  bpf_map_update_elem(&go_ssl_user_space_call_map, &tgid_goid, &nested_syscall_fd, BPF_ANY);

  return 0;
}
static __inline int probe_return_tls_conn_read_core(struct pt_regs* ctx, uint64_t id, uint32_t tgid, struct go_tls_conn_args* args, struct tgid_goid_t tgoid) {
  struct go_tls_symaddrs_t* symaddrs = bpf_map_lookup_elem(&go_tls_symaddrs_map, &tgid);
  if (symaddrs == NULL) {
    return 0;
  }
                                  
  REQUIRE_LOCATION(symaddrs->Read_retval0_loc, 0);
  REQUIRE_LOCATION(symaddrs->Read_retval1_loc, 0);     
  const void* sp = (const void*)_C(ctx,sp);
  uint64_t* regs = go_regabi_regs(ctx);
  if (regs == NULL) {
    return 0;
  }             

  int64_t retval0 = 0;
  assign_arg(&retval0, sizeof(retval0), symaddrs->Read_retval0_loc, sp, regs);

  struct go_interface retval1 = {};
  assign_arg(&retval1, sizeof(retval1), symaddrs->Read_retval1_loc, sp, regs);

   // If function returns an error, then there's no data to trace.
  if (retval1.ptr != 0) {
    return 0;
  }


  // To call get_fd_from_conn_intf, cast the conn_ptr into a go_interface.
  // TODO(oazizi): Consider changing get_fd_from_conn_intf so this is not required.

  struct go_common_symaddrs_t* common_symaddrs = bpf_map_lookup_elem(&go_common_symaddrs_map, &tgid);
  if (common_symaddrs == NULL) {
    return 0;
  }

  struct go_interface conn_intf;
  conn_intf.type = common_symaddrs->tls_Conn;
  conn_intf.ptr = args->conn_ptr;
  int fd = get_fd_from_conn_intf_core(conn_intf, common_symaddrs);
  if (fd == kInvalidFD) {
    return 0;
  }

  // syscall len
  struct nested_syscall_fd_t* nested_syscall_fd_ptr = bpf_map_lookup_elem(&go_ssl_user_space_call_map, &tgoid);
  if (nested_syscall_fd_ptr == NULL) {
      return 0;
  }

  int fd2 = nested_syscall_fd_ptr->fd;
  

  // set conn as ssl

  struct data_args read_args = {};
  read_args.source_fn = kSSLRead;
  read_args.buf = args->plaintext_ptr;
  read_args.fd = fd;

  uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
  struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
  if (conn_info) {
    conn_info->ssl = true;
    process_syscall_data_with_conn_info(ctx, &read_args, tgid_fd, kIngress, retval0, conn_info, nested_syscall_fd_ptr->syscall_len, true, true);
    
    conn_info->ssl_read_bytes += retval0;
  }
  return 0;
}

SEC("uprobe/dummy:go_tls_read")
int probe_return_tls_conn_read(struct pt_regs* ctx) {
  // bpf_printk("probe_return_tls_conn_read");
  uint64_t id = bpf_get_current_pid_tgid();
  uint32_t tgid = id >> 32;
  uint32_t pid = id;

  struct tgid_goid_t tgid_goid = {};
  tgid_goid.tgid = tgid;
  uint64_t goid = get_goid(ctx);
  if (goid == 0) {
    return 0;
  }
  tgid_goid.goid = goid;


  struct go_tls_conn_args* args = bpf_map_lookup_elem(&active_tls_conn_op_map, &tgid_goid);
  if (args == NULL) {
    return 0;
  }

  probe_return_tls_conn_read_core(ctx, id, tgid, args, tgid_goid);

  bpf_map_delete_elem(&active_tls_conn_op_map, &tgid_goid);
  bpf_map_delete_elem(&go_ssl_user_space_call_map, &tgid_goid);

  return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";