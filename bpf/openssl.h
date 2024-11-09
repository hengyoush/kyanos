//go:build ignore

// #include "../vmlinux/vmlinux.h"

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"
#include "data_common.h"

const struct kern_evt *kern_evt_unused __attribute__((unused));
const struct conn_evt_t *conn_evt_t_unused __attribute__((unused));
const struct sock_key *sock_key_unused __attribute__((unused));
const struct kern_evt_data *kern_evt_data_unused __attribute__((unused));
const struct conn_id_s_t *conn_id_s_t_unused __attribute__((unused));
const struct conn_info_t *conn_info_t_unused __attribute__((unused));
const enum conn_type_t *conn_type_t_unused __attribute__((unused));
const enum endpoint_role_t *endpoint_role_unused  __attribute__((unused));
const enum traffic_direction_t *traffic_direction_t_unused __attribute__((unused));
const enum traffic_protocol_t *traffic_protocol_t_unused __attribute__((unused));
const enum control_value_index_t *control_value_index_t_unused __attribute__((unused));
const enum step_t *step_t_unused __attribute__((unused));

static int get_fd_symaddrs(uint32_t tgid, void* ssl) {
//   struct openssl_symaddrs_t* symaddrs = openssl_symaddrs_map.lookup(&tgid);
//   if (symaddrs == NULL) {
//     return kInvalidFD;
//   }

//   REQUIRE_SYMADDR(symaddrs->SSL_rbio_offset, kInvalidFD);
//   REQUIRE_SYMADDR(symaddrs->RBIO_num_offset, kInvalidFD);

  // Extract FD via ssl->rbio->num.
  const void** rbio_ptr_addr = ssl + SSL_ST_RBIO;
  void* rbio_ptr;
  bpf_probe_read_user(&rbio_ptr, sizeof(rbio_ptr),rbio_ptr_addr);
  const int* rbio_num_addr = rbio_ptr + BIO_ST_NUM;
  int rbio_num;
  bpf_probe_read_user(&rbio_num, sizeof(rbio_num), rbio_num_addr);

  return rbio_num;
}

static __always_inline int get_fd(uint32_t tgid, void* ssl) {
  int fd = kInvalidFD;

  // OpenSSL is used by nodejs in an asynchronous way, where the SSL_read/SSL_write functions don't
  // immediately relay the traffic to/from the socket. If we notice that this SSL call was made from
  // node, we use the FD that we obtained from a separate nodejs uprobe.
//   fd = get_fd_node(tgid, ssl);
//   if (fd != kInvalidFD && /*not any of the standard fds*/ fd > 2) {
//     return fd;
//   }

  fd = get_fd_symaddrs(tgid, ssl);
  if (fd != kInvalidFD && /*not any of the standard fds*/ fd > 2) {
    return fd;
  }

  return kInvalidFD;
}


static __always_inline void process_ssl_data(struct pt_regs* ctx, uint64_t id,
                                          const enum traffic_direction_t direction,
                                           struct data_args* args, bool is_ex_call, uint32_t syscall_len) {

    int bytes_count = PT_REGS_RC(ctx);
    //SSL_write_ex and SSL_read_ex will return 1 on success
    if (bytes_count == 1 && args->ssl_ex_len != NULL) {
        size_t ex_bytes;
        bpf_probe_read_user(&ex_bytes, sizeof(size_t), args->ssl_ex_len);
        bytes_count = ex_bytes;
        // bpf_printk("exlen: %d ,bc :%d", ex_bytes, bytes_count);
    } else if (bytes_count < 0) {
        // bpf_printk("bc<0 :%d", bytes_count);
        return ;
    } else {
        // bpf_printk("bc>0 :%d", bytes_count);
    }
    uint64_t tgid_fd = gen_tgid_fd(id>>32, args->fd);
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info) {
        conn_info->ssl = true;
        process_syscall_data_with_conn_info(ctx, args, tgid_fd, direction, bytes_count, conn_info, syscall_len, true, true);
        if (direction == kEgress) {
            conn_info->ssl_write_bytes += bytes_count;
        } else {
            conn_info->ssl_read_bytes += bytes_count;
        }
    }

}

static __always_inline int do_SSL_read_entry_offset(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    char* buf = (char*)PT_REGS_PARM2(ctx);
    int32_t fd = get_fd(tgid, ssl);

    if (fd == kInvalidFD) {
        return BPF_OK;
    }


    struct data_args read_args = {};
    read_args.source_fn = kSSLRead;
    read_args.fd = fd;
    read_args.buf = buf;
    bpf_map_update_elem(&active_ssl_read_args_map, &id, &read_args, BPF_ANY);
    set_conn_as_ssl(tgid, fd);
    return BPF_OK;
}

static __always_inline int do_SSL_read_ret_offset(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args* read_args = bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (read_args != NULL) {
        process_ssl_data(ctx, id, kIngress, read_args, false, 0);
    }

    bpf_map_delete_elem(&active_ssl_read_args_map, &id);
    return 0;
}

static __always_inline int do_SSL_write_entry_offset(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    char* buf = (char*)PT_REGS_PARM2(ctx);
    int32_t fd = get_fd(tgid, ssl);

    if (fd == kInvalidFD) {
        return BPF_OK;
    }


    struct data_args write_args = {};
    write_args.source_fn = kSSLWrite;
    write_args.fd = fd;
    write_args.buf = buf;
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &write_args, BPF_ANY);
    set_conn_as_ssl(tgid, fd);
    return BPF_OK;
}


static __always_inline int do_SSL_write_ret_offset(struct pt_regs* ctx) {
    uint64_t id = bpf_get_current_pid_tgid();

    struct data_args* write_args = bpf_map_lookup_elem(&active_ssl_write_args_map, &id);
    if (write_args != NULL) {
        process_ssl_data(ctx, id, kEgress, write_args, false, 0);
    }

    bpf_map_delete_elem(&active_ssl_write_args_map, &id);
    return 0;
}

static __always_inline int do_SSL_read_entry(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    struct nested_syscall_fd_t nested_syscall_fd = {
        .fd = kInvalidFD,
        .syscall_len = 0,
    };
    nested_syscall_fd.fd = get_fd(tgid, ssl);
    bpf_map_update_elem(&ssl_user_space_call_map, &id, &nested_syscall_fd, BPF_ANY);

    char* buf = (char*)PT_REGS_PARM2(ctx);
    struct data_args read_args = {};
    read_args.source_fn = kSSLRead;
    read_args.buf = buf;
    if (is_ex_call) {
        size_t* ssl_ex_len = (size_t*)PT_REGS_PARM4(ctx);
        read_args.ssl_ex_len = ssl_ex_len;
    }
    bpf_map_update_elem(&active_ssl_read_args_map, &id, &read_args, BPF_ANY);
    return 0;
}


static __always_inline int do_SSL_read_ret(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct nested_syscall_fd_t* nested_syscall_fd_ptr = bpf_map_lookup_elem(&ssl_user_space_call_map, &id);
    if (nested_syscall_fd_ptr == NULL) {
        return 0;
    }

    int fd = nested_syscall_fd_ptr->fd;
    bpf_map_delete_elem(&ssl_user_space_call_map, &id);

    struct data_args* data_arg = bpf_map_lookup_elem(&active_ssl_read_args_map, &id);
    if (data_arg) {
        // bpf_printk("bc: %d", PT_REGS_RC(ctx));
        data_arg->fd = fd;
        process_ssl_data(ctx, id, kIngress, data_arg, is_ex_call, nested_syscall_fd_ptr->syscall_len);
    }

    return 0;
}


static __always_inline int do_SSL_write_entry(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    struct nested_syscall_fd_t nested_syscall_fd = {
        .fd = kInvalidFD,
        .syscall_len = 0,
    };
    nested_syscall_fd.fd = get_fd(tgid, ssl);
    bpf_map_update_elem(&ssl_user_space_call_map, &id, &nested_syscall_fd, BPF_ANY);

    char* buf = (char*)PT_REGS_PARM2(ctx);
    struct data_args write_args = {};
    write_args.source_fn = kSSLWrite;
    write_args.buf = buf;
    if (is_ex_call) {
        size_t* ssl_ex_len = (size_t*)PT_REGS_PARM4(ctx);
        write_args.ssl_ex_len = ssl_ex_len;
    }
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &write_args, BPF_ANY);
    return 0;
}


static __always_inline int do_SSL_write_ret(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    struct nested_syscall_fd_t* nested_syscall_fd_ptr = bpf_map_lookup_elem(&ssl_user_space_call_map, &id);
    if (nested_syscall_fd_ptr == NULL) {
        return 0;
    }

    int fd = nested_syscall_fd_ptr->fd;
    bpf_map_delete_elem(&ssl_user_space_call_map, &id);

    struct data_args* data_arg = bpf_map_lookup_elem(&active_ssl_write_args_map, &id);
    if (data_arg) {
        // bpf_printk("do_SSL_write_ret, tgid: %lld, fd: %d, bc: %d", id>>32, fd, PT_REGS_RC(ctx));
        data_arg->fd = fd;
        process_ssl_data(ctx, id, kEgress, data_arg, is_ex_call, nested_syscall_fd_ptr->syscall_len);
    }

    return 0;
}


SEC("uprobe/dummy:SSL_read")
int BPF_UPROBE(SSL_read_entry_nested_syscall) {
    // bpf_printk("SSL_read_entry_nested_syscall");
    return do_SSL_read_entry(ctx, false);
}

SEC("uretprobe/dummy:SSL_read")
int BPF_URETPROBE(SSL_read_ret_nested_syscall) {
    // bpf_printk("SSL_read_ret_nested_syscall");
    return do_SSL_read_ret(ctx, false);
}


SEC("uprobe/dummy:SSL_read_ex")
int BPF_UPROBE(SSL_read_ex_entry_nested_syscall) {
    // bpf_printk("SSL_read_ex_entry_nested_syscall");
    return do_SSL_read_entry(ctx, true);
}

SEC("uretprobe/dummy:SSL_read_ex")
int BPF_URETPROBE(SSL_read_ex_ret_nested_syscall) {
    // bpf_printk("SSL_read_ex_ret_nested_syscall");
    return do_SSL_read_ret(ctx, true);
}

SEC("uprobe/dummy:SSL_write")
int BPF_UPROBE(SSL_write_entry_nested_syscall) {
    // bpf_printk("SSL_write_entry_nested_syscall");
    return do_SSL_write_entry(ctx, false);
}

SEC("uretprobe/dummy:SSL_write")
int BPF_URETPROBE(SSL_write_ret_nested_syscall) {
    // bpf_printk("SSL_write_ret_nested_syscall");
    return do_SSL_write_ret(ctx, false);
}

SEC("uprobe/dummy:SSL_write_ex")
int BPF_UPROBE(SSL_write_ex_entry_nested_syscall) {
    // bpf_printk("SSL_write_ex_entry_nested_syscall");
    return do_SSL_write_entry(ctx, true);
}

SEC("uretprobe/dummy:SSL_write_ex")
int BPF_URETPROBE(SSL_write_ex_ret_nested_syscall) {
    // bpf_printk("SSL_write_ex_ret_nested_syscall");
    return do_SSL_write_ret(ctx, true);
}

SEC("uprobe/dummy:SSL_write")
int BPF_UPROBE(SSL_write_entry_offset) {
    // bpf_printk("SSL_write_entry_offset");
    return do_SSL_write_entry_offset(ctx, false);
}

SEC("uretprobe/dummy:SSL_write")
int BPF_URETPROBE(SSL_write_ret_offset) {
    // bpf_printk("SSL_write_ret_offset");
    return do_SSL_write_ret_offset(ctx);
}

SEC("uprobe/dummy:SSL_read")
int BPF_UPROBE(SSL_read_entry_offset) {
    // bpf_printk("SSL_read_entry_offset");
    return do_SSL_read_entry_offset(ctx, false);
}

SEC("uretprobe/dummy:SSL_read")
int BPF_URETPROBE(SSL_read_ret_offset) {
    // bpf_printk("SSL_read_ret_offset");
    return do_SSL_read_ret_offset(ctx);
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";