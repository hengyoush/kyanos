//go:build ignore

#include "../vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"
#include "data_common.h"

static __always_inline int do_SSL_read_entry(struct pt_regs* ctx, bool is_ex_call) {
    uint64_t id = bpf_get_current_pid_tgid();
    uint32_t tgid = id >> 32;
    
    void* ssl = (void*)PT_REGS_PARM1(ctx);
    struct nested_syscall_fd_t nested_syscall_fd = {
        .fd = kInvalidFD,
    };
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

static __always_inline void process_ssl_data(struct pt_regs* ctx, uint64_t id,
                                          const enum traffic_direction_t direction,
                                          const struct data_args* args, bool is_ex_call) {

    int bytes_count = PT_REGS_RC(ctx);
    //SSL_write_ex and SSL_read_ex will return 1 on success
    if (bytes_count == 1 && args->ssl_ex_len != NULL) {
        size_t ex_bytes;
        bpf_probe_read_kernel(&ex_bytes, sizeof(size_t), &args->ssl_ex_len);
        bytes_count = ex_bytes;
    }                                        
    uint64_t tgid_fd = gen_tgid_fd(id>>32, args->fd);
    struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
    if (conn_info) {
        process_syscall_data_with_conn_info(ctx, args, tgid_fd, direction, bytes_count, conn_info);
    }
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
        data_arg->fd = fd;
        process_ssl_data(ctx, id, kIngress, data_arg, is_ex_call);
    }

    return 0;
}

SEC("uprobe/dummy:func")
int BPF_UPROBE(SSL_read_entry) {
    do_SSL_read_entry(ctx, false);
}

SEC("uretprobe/dummy:func")
int BPF_URETPROBE(SSL_read_ret) {
    // 返回的时候获取fd，然后通过tgidfd拿到conninfo，设置ssl=true -- conninfomap
    // 然后拿到数据，推断协议，上报数据 -- data map
    return do_SSL_read_ret(ctx, false);
}