#ifndef _DATA_COMMON_H__
#define _DATA_COMMON_H__

#include "protocol_inference.h"

const struct kern_evt_ssl_data *kern_evt_ssl_data_unused __attribute__((unused));
struct nested_syscall_fd_t {
    int fd;
    bool mismatched_fds;
	uint32_t syscall_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_mntns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_pidns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_netns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_pid_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(uint64_t));
	__uint(value_size, sizeof(struct data_args));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} active_ssl_read_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(uint64_t));
	__uint(value_size, sizeof(struct data_args));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} active_ssl_write_args_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(uint64_t));
	__uint(value_size, sizeof(struct nested_syscall_fd_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} ssl_user_space_call_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} rb SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} syscall_rb SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} ssl_rb SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} conn_evt_rb SEC(".maps");

MY_BPF_HASH(conn_info_map, uint64_t, struct conn_info_t);
MY_BPF_ARRAY_PERCPU(syscall_data_map, struct kern_evt_data)
MY_BPF_ARRAY_PERCPU(ssl_data_map, struct kern_evt_ssl_data)

const int32_t kInvalidFD = -1;



static bool __always_inline report_conn_evt(void* ctx, struct conn_info_t *conn_info, enum conn_type_t type, uint64_t ts) {
	struct conn_evt_t _evt = {0};
	struct conn_evt_t* evt = &_evt;
	if (!evt) {
		return 0;
	}
	// evt->conn_info = *conn_info;
	bpf_probe_read_kernel(&evt->conn_info, sizeof(struct conn_info_t), conn_info);
	evt->conn_type = type;
	if (ts != 0) {
		evt->ts = ts;
	} else {
		evt->ts = bpf_ktime_get_ns();
	}
	bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_evt_t));
	return 1;
}

static __inline bool should_trace_conn(struct conn_info_t *conn_info) {
	// conn_info->laddr.in4.sin_port
	// bpf_printk("conn_info->laddr.in4.sin_port: %d, %d", 
	// 	conn_info->laddr.in4.sin_port,conn_info->raddr.in4.sin_port);
	// if (conn_info->laddr.in4.sin_port == target_port || 
	// 	conn_info->raddr.in4.sin_port == target_port) {
	// 		return true;
	// }

	return conn_info->protocol != kProtocolUnknown && !conn_info->no_trace;
}

static void __always_inline report_syscall_buf_without_data(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, size_t len, enum step_t step, uint64_t ts, enum source_function_t source_fn) {
	size_t _len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
	if (_len == 0) {
		return;
	}
	
	int zero = 0;
	struct kern_evt_data* evt = bpf_map_lookup_elem(&syscall_data_map, &zero);
	if(!evt || !conn_id_s) {
		return;
	}
	evt->ke.conn_id_s = *conn_id_s;
	evt->ke.seq = seq;
	evt->ke.len = len;
	evt->ke.step = step;
	if (ts != 0) {
		evt->ke.ts = ts;
	} else {
		evt->ke.ts = bpf_ktime_get_ns();
	}
	evt->buf_size = 0; 

	size_t __len = sizeof(struct kern_evt) + sizeof(uint32_t);
	bpf_perf_event_output(ctx, &syscall_rb, BPF_F_CURRENT_CPU, evt, __len);
}
static void __always_inline report_syscall_buf(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, size_t len, enum step_t step, uint64_t ts, const char* buf, enum source_function_t source_fn) {
	size_t _len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
	if (_len == 0) {
		return;
	}
	
	int zero = 0;
	struct kern_evt_data* evt = bpf_map_lookup_elem(&syscall_data_map, &zero);
	if(!evt || !conn_id_s) {
		return;
	}
	evt->ke.conn_id_s = *conn_id_s;
	evt->ke.seq = seq;
	evt->ke.len = len;
	evt->ke.step = step;
	if (ts != 0) {
		evt->ke.ts = ts;
	} else {
		evt->ke.ts = bpf_ktime_get_ns();
	}
	evt->buf_size = _len; 

	size_t len_minus_1 = _len - 1;
	asm volatile("" : "+r"(len_minus_1) :);
	_len = len_minus_1 + 1;
	size_t amount_copied = 0;
	if (len_minus_1 < MAX_MSG_SIZE) {
		bpf_probe_read(evt->msg, _len, buf);
		amount_copied = _len;
	} else if (len_minus_1 < 0x7fffffff) {
		bpf_probe_read(evt->msg, MAX_MSG_SIZE, buf);
		amount_copied = MAX_MSG_SIZE;
	}
	evt->buf_size = amount_copied; 
	size_t __len = sizeof(struct kern_evt) + sizeof(uint32_t) + amount_copied;
	bpf_perf_event_output(ctx, &syscall_rb, BPF_F_CURRENT_CPU, evt, __len);
}
static void __always_inline report_syscall_evt(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, uint32_t len, enum step_t step, struct data_args *args) {
	report_syscall_buf(ctx, seq, conn_id_s, len, step, args->ts, args->buf, args->source_fn);
}

static void __always_inline report_ssl_buf(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, size_t len, enum step_t step, uint64_t ts, const char* buf, enum source_function_t source_fn, uint32_t syscall_seq, uint32_t syscall_len) {
	size_t _len = len < MAX_MSG_SIZE ? len : MAX_MSG_SIZE;
	if (_len == 0) {
		return;
	}
	
	int zero = 0;
	struct kern_evt_ssl_data* evt = bpf_map_lookup_elem(&ssl_data_map, &zero);
	if(!evt || !conn_id_s) {
		return;
	}
	evt->ke.conn_id_s = *conn_id_s;
	evt->ke.seq = seq;
	evt->ke.len = len;
	evt->ke.step = step;
	if (ts != 0) {
		evt->ke.ts = ts;
	} else {
		evt->ke.ts = bpf_ktime_get_ns();
	}
	evt->buf_size = _len; 
	evt->syscall_len = syscall_len;
	evt->syscall_seq = syscall_seq;

	size_t len_minus_1 = _len - 1;
	asm volatile("" : "+r"(len_minus_1) :);
	_len = len_minus_1 + 1;
	size_t amount_copied = 0;
	if (len_minus_1 < MAX_MSG_SIZE) {
		bpf_probe_read(evt->msg, _len, buf);
		amount_copied = _len;
	} else if (len_minus_1 < 0x7fffffff) {
		bpf_probe_read(evt->msg, MAX_MSG_SIZE, buf);
		amount_copied = MAX_MSG_SIZE;
	}
	evt->buf_size = amount_copied; 
	size_t __len = sizeof(struct kern_evt) + sizeof(uint32_t) + sizeof(uint64_t)+ sizeof(uint32_t) + amount_copied;
	bpf_perf_event_output(ctx, &ssl_rb, BPF_F_CURRENT_CPU, evt, __len);
}
static void __always_inline report_ssl_evt(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, uint32_t len, enum step_t step, struct data_args *args, uint32_t syscall_seq, uint32_t syscall_len) {
	report_ssl_buf(ctx, seq, conn_id_s, len, step, args->ts, args->buf, args->source_fn, syscall_seq, syscall_len);
}
static void __always_inline report_syscall_evt_vecs(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, uint32_t total_size, enum step_t step, struct data_args *args) {
	int bytes_sent = 0;
#pragma unroll
	for (int i = 0; i < LOOP_LIMIT && i < args->iovlen && bytes_sent < total_size; ++i) {
    	struct iovec iov_cpy;
		bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &args->iov[i]);
		const int bytes_remaining = total_size - bytes_sent;
		const size_t iov_size = iov_cpy.iov_len < bytes_remaining ? iov_cpy.iov_len : bytes_remaining;
		report_syscall_buf(ctx, seq, conn_id_s, iov_size, step, args->ts, iov_cpy.iov_base, args->source_fn);
		bytes_sent += iov_size;
		seq += iov_size;
	}
}


static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
  return ((uint64_t)tgid << 32) | (uint32_t)fd;
}
static __always_inline void process_syscall_data_with_conn_info(void* ctx, struct data_args *args, uint64_t tgid_fd,
 enum traffic_direction_t direct,ssize_t bytes_count, struct conn_info_t* conn_info, int32_t syscall_len, bool is_ssl, bool with_data) {
	bool inferred = false;
	if (conn_info->protocol == kProtocolUnset || conn_info->protocol == kProtocolUnknown) {
		enum traffic_protocol_t before_infer = conn_info->protocol;
		// bpf_printk("[protocol infer]:start, bc:%d", bytes_count);
		// conn_info->protocol = protocol_message.protocol;
		struct protocol_message_t protocol_message = infer_protocol(args->buf, bytes_count, conn_info);
		if (before_infer != protocol_message.protocol) {
			conn_info->protocol = protocol_message.protocol;
			// bpf_printk("[protocol infer]: %d, func: %d", conn_info->protocol, args->source_fn);
			
			if (conn_info->role == kRoleUnknown && protocol_message.type != kUnknown) {
				conn_info->role = ((direct == kEgress) ^ (protocol_message.type == kResponse))
									? kRoleClient
									: kRoleServer;
			}
			inferred = true;
			report_conn_evt(ctx, conn_info, kProtocolInfer, 0);
		}
	}
	// bpf_printk("start trace data!, bytes_count:%d,func:%d", bytes_count, args->source_fn);
	uint64_t seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
	struct conn_id_s_t conn_id_s;
	conn_id_s.tgid_fd = tgid_fd;
	// conn_id_s.direct = direct;
	enum step_t step;
	if (is_ssl) {
		step = direct == kEgress ? SSL_OUT : SSL_IN;
	} else {
		step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
	}
	 
	if (conn_info->protocol != kProtocolUnknown && (inferred || !conn_info->no_trace)) {//, bytes_count
		if (is_ssl) {
			uint64_t syscall_seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
			seq = (direct == kEgress ?  conn_info->ssl_write_bytes : conn_info->ssl_read_bytes) + 1;
			report_ssl_evt(ctx, seq, &conn_id_s, bytes_count, step, args, syscall_len < 0 ? 0 : (syscall_seq - syscall_len), syscall_len < 0 ? 0 : syscall_len);
			// bpf_printk("report ssl evt, seq: %lld len: %d",)
		} else if (with_data) {
			report_syscall_evt(ctx, seq, &conn_id_s, bytes_count, step, args);
		} else {
			report_syscall_buf_without_data(ctx, seq, &conn_id_s, bytes_count, step, args->ts, args->source_fn);
		}
	}
}


static __inline void set_conn_as_ssl(uint32_t tgid, int32_t fd) {
	uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
	struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (conn_info == NULL) {
		return;
	}
	conn_info->ssl = true;
}


#endif