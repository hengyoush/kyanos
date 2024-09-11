//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "../vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"

#include "protocol_inference.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define ETH_P_IP	0x0800
#define ETH_HLEN	14		/* Total octets in header.	 */

#define _(src)							\
({								\
	typeof(src) tmp;					\
	bpf_probe_read_kernel(&tmp, sizeof(src), &(src));	\
	tmp;							\
})


#define _C(src, a, ...)		BPF_CORE_READ(src, a, ##__VA_ARGS__)

#define _U(src, a, ...)		BPF_PROBE_READ_USER(src, a, ##__VA_ARGS__)

#ifdef BPF_DEBUG
#define pr_bpf_debug(fmt, args...) {				\
	bpf_printk("nettrace: "fmt"\n", ##args);	\
}
#else
#define pr_bpf_debug(fmt, ...) 
#endif


#define IP_H_LEN	(sizeof(struct iphdr))
#define PROTOCOL_VEC_LIMIT 3
#define LOOP_LIMIT 2


#define TP_ARGS(dst, idx, ctx) \
{void *__p = (void*)ctx + sizeof(struct trace_entry) + sizeof(long int) + idx * (sizeof(long unsigned int)); \
bpf_probe_read_kernel(dst, sizeof(*dst), __p);}

#define TP_RET(dst, ctx) \
{void *__p = (void*)ctx + sizeof(struct trace_entry) + sizeof(long int); \
bpf_probe_read_kernel(dst, sizeof(*dst), __p); }


#define MY_BPF_HASH(name, key_type, value_type) \
struct {													\
	__uint(type, BPF_MAP_TYPE_HASH); \
	__uint(key_size, sizeof(key_type)); \
	__uint(value_size, sizeof(value_type)); \
	__uint(max_entries, 65535); \
	__uint(map_flags, 0); \
} name SEC(".maps");

#define MY_BPF_ARRAY_PERCPU(name, value_type) \
struct {													\
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
	__uint(key_size, sizeof(__u32)); \
	__uint(value_size, sizeof(value_type)); \
	__uint(max_entries, 1); \
	__uint(map_flags, 0); \
} name SEC(".maps");


const struct kern_evt *kern_evt_unused __attribute__((unused));
const struct conn_evt_t *conn_evt_t_unused __attribute__((unused));
const struct sock_key *sock_key_unused __attribute__((unused));
const struct kern_evt_data *kern_evt_data_unused __attribute__((unused));
const struct conn_info_t *conn_info_t_unused __attribute__((unused));
const enum conn_type_t *conn_type_t_unused __attribute__((unused));
const enum endpoint_role_t *endpoint_role_unused  __attribute__((unused));
const enum traffic_direction_t *traffic_direction_t_unused __attribute__((unused));
const enum traffic_protocol_t *traffic_protocol_t_unused __attribute__((unused));
const enum control_value_index_t *control_value_index_t_unused __attribute__((unused));
const enum step_t *step_t_unused __attribute__((unused));

static __always_inline bool skb_l2_check(u16 header) 
{
	return !header || header == (u16)~0U;
}
static __always_inline bool skb_l4_check(u16 l4, u16 l3)
{
	return l4 == 0xFFFF || l4 <= l3;
}
static __always_inline struct tcphdr* parse_tcp_hdr(struct iphdr* iph, void* data_end) {
    struct tcphdr* tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }
    if ((void*)iph + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
        return NULL;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NULL;
    }
    tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
    return tcph;
}
static __always_inline u8 get_ip_header_len(u8 h)
{
	u8 len = (h & 0x0F) * 4;
	return len > IP_H_LEN ? len: IP_H_LEN;
}
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_xmit_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(struct conn_id_s_t));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} sock_key_conn_id_map SEC(".maps");

MY_BPF_HASH(conn_info_map, uint64_t, struct conn_info_t);
MY_BPF_ARRAY_PERCPU(syscall_data_map, struct kern_evt_data)

#ifdef KERNEL_VERSION_BELOW_58 
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
} conn_evt_rb SEC(".maps");
#else
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<24);
} rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<24);
} syscall_rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} conn_evt_rb SEC(".maps");
#endif

MY_BPF_HASH(control_values, uint32_t, int64_t)

enum target_tgid_match_result_t {
  TARGET_TGID_UNSPECIFIED,
  TARGET_TGID_ALL,
  TARGET_TGID_MATCHED,
  TARGET_TGID_UNMATCHED,
};
static __inline enum target_tgid_match_result_t match_trace_tgid(const uint32_t tgid) {
  // TODO(yzhao): Use externally-defined macro to replace BPF_MAP. Since this function is called for
  // all PIDs, this optimization is useful.
  uint32_t idx = kTargetTGIDIndex;
  int64_t* target_tgid = bpf_map_lookup_elem(&control_values, &idx);
  if (target_tgid == NULL) {
    return TARGET_TGID_UNSPECIFIED;
  }
  if (*target_tgid < 0) {
    // Negative value means trace all.
    return TARGET_TGID_ALL;
  }
  if (*target_tgid == tgid) {
    return TARGET_TGID_MATCHED;
  }
  return TARGET_TGID_UNMATCHED;
// return TARGET_TGID_UNSPECIFIED;
}

static __always_inline struct sock_key reverse_sock_key(struct sock_key* key) {
	struct sock_key copy;
	copy.dip = key->sip;
	copy.dport = key->sport;
	copy.sip = key->dip;
	copy.sport = key->dport;
	copy.family = key->family;
	return copy;
}
static void __always_inline parse_kern_evt_body(struct parse_kern_evt_body *param) {
	void* ctx = param->ctx;
	u32 inital_seq = param->inital_seq;
	struct sock_key *key = param->key;
	u32 cur_seq = param->cur_seq;
	u32 len = param->len;
	const char *func_name = param->func_name;
	enum step_t step = param->step;
#ifdef KERNEL_VERSION_BELOW_58 
	struct kern_evt _evt = {0};
	struct kern_evt* evt = &_evt;
#else
	struct kern_evt* evt = bpf_ringbuf_reserve(&rb, sizeof(struct kern_evt), 0); 
#endif
	if(!evt) {
		return;
	}
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
#ifdef KERNEL_VERSION_BELOW_58 
#else
	if (conn_id_s == NULL) {
		bpf_ringbuf_discard(evt, 0);
		return;
	}
#endif
	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	evt->seq = cur_seq; 
	u32 bl_bdr = evt->seq;
	// u32 doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
	// u64 hdr_len = doff << 2;
	u32 br_bdr = bl_bdr + len;
	evt->len = br_bdr - bl_bdr; 
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	bpf_probe_read_kernel(evt->func_name,FUNC_NAME_LIMIT, func_name);
	// my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);
#ifdef KERNEL_VERSION_BELOW_58
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, evt, sizeof(_evt));
#else
	bpf_ringbuf_submit(evt, 0);
#endif
}
// static __always_inline void  report_kern_evt(void* ctx, u32 seq, struct sock_key* key,struct tcphdr* tcp, int len, char* func_name, enum step_t step) {
static __always_inline void  report_kern_evt(struct parse_kern_evt_body *param) {
	void* ctx = param->ctx;
	u32 seq = param->inital_seq;
	struct sock_key *key = param->key;
	struct tcphdr* tcp = param->tcp;
	int len = param->len;
	const char *func_name = param->func_name;
	enum step_t step = param->step;
#ifdef KERNEL_VERSION_BELOW_58 
	struct kern_evt _evt = {0};
	struct kern_evt* evt = &_evt;
#else
	struct kern_evt* evt = bpf_ringbuf_reserve(&rb, sizeof(struct kern_evt), 0); 
	if(!evt) {
		return;
	}
#endif
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
#ifdef KERNEL_VERSION_BELOW_58 
#else
	if (conn_id_s == NULL) {
		bpf_ringbuf_discard(evt, 0);
		return;
	}
#endif
	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	u32 tcpseq = 0;
	BPF_CORE_READ_INTO(&tcpseq, tcp, seq);
	tcpseq  = bpf_htonl(tcpseq);
	evt->seq = (uint64_t)(tcpseq - seq); 
	// evt->tcp_seq = bpf_ntohl(_(tcp->seq));
	u32 bl_bdr = evt->seq;
	u32 doff = 0;
	bpf_probe_read_kernel(&doff, sizeof(doff), (void*)tcp + 12);
	doff = (doff&255) >> 4;
	u64 hdr_len = doff << 2;
	u32 br_bdr = bl_bdr + len - hdr_len;
	evt->len = br_bdr - bl_bdr;
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	// evt->flags = _(((u8 *)tcp)[13]);
	// bpf_probe_read_kernel(&evt->flags, sizeof(((u8 *)tcp)[13]), &(((u8 *)tcp)[13]));
	// bpf_probe_read_kernel(evt->func_name,FUNC_NAME_LIMIT, func_name);
	// my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);

#ifdef KERNEL_VERSION_BELOW_58
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, evt, sizeof(struct kern_evt));
#else
	bpf_ringbuf_submit(evt, 0);
#endif
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
#ifdef KERNEL_VERSION_BELOW_58
	bpf_perf_event_output(ctx, &syscall_rb, BPF_F_CURRENT_CPU, evt, __len);
#else
	bpf_ringbuf_output(&syscall_rb, evt, __len, 0);
#endif
}
static void __always_inline report_syscall_evt(void* ctx, uint64_t seq, struct conn_id_s_t *conn_id_s, uint32_t len, enum step_t step, struct data_args *args) {
	report_syscall_buf(ctx, seq, conn_id_s, len, step, args->ts, args->buf, args->source_fn);
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


static bool __always_inline report_conn_evt(void* ctx, struct conn_info_t *conn_info, enum conn_type_t type, uint64_t ts) {
#ifdef KERNEL_VERSION_BELOW_58 
	struct conn_evt_t _evt = {0};
	struct conn_evt_t* evt = &_evt;
#else
	struct conn_evt_t* evt = bpf_ringbuf_reserve(&conn_evt_rb, sizeof(struct conn_evt_t), 0); 
#endif	
	if (!evt) {
		return 0;
	}
	evt->conn_info = *conn_info;
	evt->conn_type = type;
	if (ts != 0) {
		evt->ts = ts;
	} else {
		evt->ts = bpf_ktime_get_ns();
	}
#ifdef KERNEL_VERSION_BELOW_58 
	bpf_perf_event_output(ctx, &conn_evt_rb, BPF_F_CURRENT_CPU, evt, sizeof(struct conn_evt_t));
#else
	bpf_ringbuf_submit(evt, 0);
#endif	
	return 1;
}

static void __always_inline debug_evt(struct kern_evt* evt, const char* func_name) {
	// bpf_printk("KPROBE ENTRY, func: %s, lip: %d, dip:%d",func_name, evt.key->sip, evt.key->dip);
	// bpf_printk("KPROBE ENTRY, lport: %d, dport:%d, seq: %u", evt.key->sport, evt.key->dport, evt->tcp_seq);
	// bpf_printk("KPROBE ENTRY init_seq = %u, cur_seq: %u, len: %d\n",evt->init_seq, evt->cur_seq,evt->data_len);
	// bpf_printk("is_sample: %d, ts: %u, inode: %d\n", evt->is_sample, evt->ts, evt->inode);
}
#define DEBUG 0
static void __always_inline parse_sock_key_rcv_sk(struct sock* sk, struct sock_key* key) {

	// key->sip = _C(sk, __sk_common.skc_daddr);
	// key->dip = _C(sk, __sk_common.skc_rcv_saddr);
	// key->dport =  _C(sk, __sk_common.skc_num);
	// key->sport = bpf_ntohs(_C(sk, __sk_common.skc_dport));
	// key->family = _C(sk, __sk_common.skc_family);


	BPF_CORE_READ_INTO(&key->sip,sk,__sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&key->dip,sk,__sk_common.skc_rcv_saddr);
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_num);
	BPF_CORE_READ_INTO(&sport,sk,__sk_common.skc_dport);
	sport = bpf_ntohs(sport);
	unsigned short	family = 0;
	BPF_CORE_READ_INTO(&family,sk,__sk_common.skc_family);
	key->dport = dport;
	key->sport = sport;
	key->family = family;
	// key->family = 0;
}
static void __always_inline parse_sock_key_rcv(struct sk_buff *skb, struct sock_key* key) {
	struct sock* sk = {0};
	BPF_CORE_READ_INTO(&sk, skb, sk);
	parse_sock_key_rcv_sk(sk, key);
}
static void __always_inline print_sock_key(struct sock_key* key) {
	// pr_bpf_debug("print_sock_key port: sport:%u, dport:%u", key->sport, key->dport);
	// pr_bpf_debug("print_sock_key addr: saddr:%u, daddr:%u", key->sip, key->dip);
	// pr_bpf_debug("print_sock_key family: family:%u", key->family);
}
static void __always_inline parse_sock_key_sk(struct sock* sk, struct sock_key* key) {
	BPF_CORE_READ_INTO(&key->dip,sk,__sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&key->sip,sk,__sk_common.skc_rcv_saddr);
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&sport,sk,__sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
	dport = bpf_ntohs(dport);
	unsigned short	family = 0;
	BPF_CORE_READ_INTO(&family,sk,__sk_common.skc_family);
	key->dport = dport;
	key->sport = sport;
	key->family = family;
	// key->dip = _C(sk, __sk_common.skc_daddr);
	// key->sip = _C(sk, __sk_common.skc_rcv_saddr);
	// key->sport =  _C(sk, __sk_common.skc_num);
	// key->dport = bpf_ntohs(_C(sk, __sk_common.skc_dport));
	// key->family = _C(sk, __sk_common.skc_family);
	// key->family = 0;

}
static void __always_inline parse_sock_key(struct sk_buff *skb, struct sock_key* key) {

	struct sock* _sk = {0};
	BPF_CORE_READ_INTO(&_sk,skb,sk);
	parse_sock_key_sk(_sk, key);
}

static void __always_inline parse_sk_l3l4(struct sock_key *key, struct iphdr *ipv4, 
	struct tcphdr *tcp) {
	u32 saddr = 0;
	u32 daddr = 0;
	BPF_CORE_READ_INTO(&saddr, ipv4, saddr);
	BPF_CORE_READ_INTO(&daddr, ipv4, daddr);
	// saddr = _C(ipv4,saddr);
	// daddr = _C(ipv4,daddr);
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&sport, tcp, source);
	BPF_CORE_READ_INTO(&dport, tcp, dest);
	key->sip = saddr;
	key->dip = daddr;
	key->sport = bpf_ntohs(sport);
	key->dport = bpf_ntohs(dport);
	key->family = AF_INET; // @ipv6

	// u32 saddr, daddr;
	// saddr = _C(ipv4,saddr);
	// daddr = _C(ipv4,daddr);
	//  sport = bpf_htons(_C(tcp,source));
	//  dport = bpf_htons(_C(tcp,dest));
	// key->sip = saddr;
	// key->dip = daddr;
	// key->sport = sport;
	// key->dport = dport;
	// key->family = AF_INET; // @ipv6
}

static __inline bool should_trace_conn(struct conn_info_t *conn_info) {
	// conn_info->laddr.in4.sin_port
	// bpf_printk("conn_info->laddr.in4.sin_port: %d, %d", 
	// 	conn_info->laddr.in4.sin_port,conn_info->raddr.in4.sin_port);
	// if (conn_info->laddr.in4.sin_port == target_port || 
	// 	conn_info->raddr.in4.sin_port == target_port) {
	// 		return true;
	// }

	return conn_info->protocol != kProtocolUnknown;
}
static bool __always_inline should_trace_sock_key(struct sock_key *key) {
	struct conn_id_s_t *conn_id_s = {0};
	conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
	if (conn_id_s == NULL) {
		// 可能还在握手
		return true;
	}
	struct conn_info_t *conn_info = {0};
	u64 tgidfd = conn_id_s->tgid_fd;
	conn_info = bpf_map_lookup_elem(&conn_info_map, &tgidfd);
	if (conn_info == NULL) {
		// why?
		return true;
	}
	return should_trace_conn(conn_info);
}

static __always_inline int enabledXDP() {
	uint32_t idx = kEnabledXdpIndex;
	int64_t* enabled = bpf_map_lookup_elem(&control_values, &idx);
	if (enabled == NULL) {
		return 1;
	}
	if (*enabled == 1) {
		return 1;
	} else {
		return 0;
	}
}

static __always_inline int parse_skb(void* ctx, struct sk_buff *skb, bool sk_not_ready, enum step_t step) {
	// return BPF_OK;
	if (skb == NULL) {
		return BPF_OK;
	}
	struct sock* sk = {0};
	BPF_CORE_READ_INTO(&sk, skb, sk);
	
	u32 inital_seq = 0;
	struct sock_key key = {0};
	if (sk) {
		struct sock_common sk_cm  = {0};
		BPF_CORE_READ_INTO(&sk_cm, sk, __sk_common);
		if (sk_cm.skc_addrpair && !sk_not_ready) {
			parse_sock_key(skb, &key);
			int  *found = {0};
			found = bpf_map_lookup_elem(&sock_xmit_map, &key);
			if (found == NULL) { 
				return 0;
			}
			if (!should_trace_sock_key(&key)) {
				return 0;
			}
			bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
		} 	
	}

	u16 network_header = 0;
	BPF_CORE_READ_INTO(&network_header, skb, network_header);
	u16 mac_header  = 0;
	BPF_CORE_READ_INTO(&mac_header, skb, mac_header);
	u16 trans_header = 0;
	BPF_CORE_READ_INTO(&trans_header, skb, transport_header);
	
	// pr_bpf_debug("%s, len: %u, data_len: %u",func_name, _C(skb, len), _C(skb, data_len));
	// pr_bpf_debug("%s, mac_header: %d", func_name,mac_header);
	// pr_bpf_debug("%s, network_header: %d", func_name,network_header);
	// pr_bpf_debug("%s, trans_header: %d", func_name,trans_header);
	// pr_bpf_debug("data:%d,end: %d, tail: %d",_C(skb,data) - _C(skb,head), _C(skb,end), _C(skb,tail));

	bool is_l2 = !skb_l2_check(mac_header);
	// pr_bpf_debug("%s, skb_l2_check: %d", func_name, is_l2);
	void* data = {0};
	BPF_CORE_READ_INTO(&data, skb, head);
	void* ip = data + network_header;
	void *l3 = {0};
	void* l4 = NULL;
	if (is_l2) {
		goto __l2;
	} else {
		u16 _protocol = 0;
		BPF_CORE_READ_INTO(&_protocol, skb, protocol);
		u16 l3_proto = bpf_ntohs(_protocol);
		// bpf_printk("%s, l3_proto: %x", func_name, l3_proto);
		if (l3_proto == ETH_P_IP) {
			// bpf_printk("%s, is_ip: %d", func_name, 1);
			l3 = data + network_header;
			goto __l3;
		} else if (mac_header == network_header) {
			l3 = data + network_header;
			l3_proto = ETH_P_IP;
			goto __l3;
		}
				
		// pr_bpf_debug("%s, is_ip: %d", func_name,0);
		goto err;
	}
	__l2: if (mac_header != network_header) {
		struct ethhdr *eth = data + mac_header;
		l3 = (void *)eth + ETH_HLEN;
		u16 l3_proto = 0;
		BPF_CORE_READ_INTO(&l3_proto, eth, h_proto);
		l3_proto = bpf_ntohs(l3_proto);
		// bpf_printk("%s, l3_proto: %x",func_name, l3_proto);
		if (l3_proto == ETH_P_IP) {
	__l3:	
			if (!skb_l4_check(trans_header, network_header)) {
				// 存在l4
				// bpf_printk("%s, skb_l4_check: %d",func_name, 0);
				l4 = data + trans_header;
			}
			struct iphdr *ipv4 = ip;
			u16 tot_len16 = 0;
			BPF_CORE_READ_INTO(&tot_len16, ipv4, tot_len);
			u32 len  = bpf_ntohs(tot_len16);
			u8 ip_hdr_len = 0;
			bpf_probe_read_kernel(&ip_hdr_len, sizeof(((u8 *)ip)[0]), &(((u8 *)ip)[0]));
			ip_hdr_len = get_ip_header_len(ip_hdr_len); 
			// bpf_printk("%s, ip_hdr_len: %d, tot_len: %d",func_name, ip_hdr_len, len);
			l4 = l4 ? l4 : ip + ip_hdr_len;
			u8 proto_l4 = 0;
			BPF_CORE_READ_INTO(&proto_l4, ipv4, protocol);
			// bpf_printk("%s, l4p: %d",func_name, proto_l4);
			if (proto_l4 == IPPROTO_TCP) {
				struct tcphdr *tcp = l4;
				if (!inital_seq) {
					// 在这里补充sk
					parse_sk_l3l4(&key, ipv4, tcp);
					// if (key.dport != target_port && key.sport != target_port) {
					// 	goto err;
					// }
					if (!should_trace_sock_key(&key)) {
						goto err;
					}
					int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
					if (found == NULL) {
						if (step == DEV_IN && enabledXDP() != 1 && should_trace_sock_key(&key)) {
							BPF_CORE_READ_INTO(&inital_seq, tcp, seq);
							inital_seq = bpf_ntohl(inital_seq);
							bpf_map_update_elem(&sock_xmit_map, &key, &inital_seq, BPF_NOEXIST);
						} else {
							goto err;
						}
					} else {
						bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
					}
				} 
				struct parse_kern_evt_body body = {0};
				body.ctx = ctx;
				body.inital_seq = inital_seq;
				body.key = &key;
				body.tcp = tcp;
				body.len = len - ip_hdr_len;
				// body.func_name = func_name;
				body.step = step;	
				report_kern_evt(&body);
				return 1;
			} else {
				// bpf_printk("%s, not match: %d", func_name, _C(ipv4,saddr));
			}
		}
	}
	err:return BPF_OK;
}

#ifndef KERNEL_VERSION_BELOW_58
SEC("xdp")
int xdp_proxy(struct xdp_md *ctx){
	// bpf_printk("xdp");
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) {
		// pr_bpf_debug("xdp2 data + sizeof(struct ethhdr) > data_end");
		return XDP_PASS;
	}
	u16 l3_proto = _(eth->h_proto);
	// bpf_printk("xdp, l3_proto: %x", l3_proto);
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		// pr_bpf_debug("xdp2 data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end");
		return XDP_ABORTED;
	}
	if (iph->protocol != IPPROTO_TCP)
	{
		// bpf_printk("xdp2 iph->protocol != IPPROTO_TCP, %x", iph->protocol);
		return XDP_PASS;
	}
	struct tcphdr* th = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
		// pr_bpf_debug("xdp2 data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end");
		return XDP_ABORTED;
	}
	
	struct sock_key key = {0};
	key.sip = _C(iph,saddr);
	key.dip = _C(iph,daddr);
	key.sport = bpf_ntohs(_C(th,source));
	key.dport = bpf_ntohs(_C(th,dest));
	key.family = AF_INET;
	// bpf_printk("xdp, not found!, sport:%d, dport:%d, family:%d", key.sport, key.dport,key.family);
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (found == NULL && !should_trace_sock_key(&key)) {
		// pr_bpf_debug("xdp key.dport != target_port, %u,%u,should_trace_sock_key:%d", key.dport, key.sport,should_trace_sock_key(&key));
		return XDP_PASS;
	}
	u32 inital_seq;
	if (found == NULL) {
		inital_seq = bpf_ntohl(th->seq);
		bpf_map_update_elem(&sock_xmit_map, &key,&inital_seq, BPF_NOEXIST);
		// bpf_printk("xdp not found!, seq: %u", inital_seq);
		// bpf_printk("xdp, not found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
		// bpf_printk("xdp, not found!, sport:%d, dport:%d, family:%d", key.sport, key.dport,key.family);
	} else {
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
		// bpf_printk("xdp found!, seq: %u", inital_seq);
	}
	u32 len = data_end - data - (sizeof(struct ethhdr) + sizeof(struct iphdr));
	// bpf_printk("xdp, skb: %x", data);
	struct parse_kern_evt_body body = {0};
	body.ctx = ctx;
	body.inital_seq = inital_seq;
	body.key = &key;
	body.tcp = th;
	body.len = len;
	// body.func_name = XDP_FUNC_NAME;
	body.step = NIC_IN;	
	report_kern_evt(&body);
	// KERN_EVENT_HANDLE(&evt, "xdp");
	return XDP_PASS; 
}
#else
#endif

static __always_inline int handle_skb_data_copy(void *ctx, struct sk_buff *skb, int offset, struct iov_iter *to, int len) {
	struct sock_key key = {0};
	parse_sock_key_rcv(skb, &key);
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (!found) {
		// bpf_printk("skb_copy_datagram_iter, not found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
		// bpf_printk("skb_copy_datagram_iter, not found!, sport:%d, dport:%d,family:%d", key.sport, key.dport, key.family);
		return BPF_OK;
	}
	if (!should_trace_sock_key(&key)) {
		return BPF_OK;
	}
	u32 inital_seq = 0;
	bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
	// bpf_printk("skb_copy_datagram_iter, found!, sip: %u, dip:%u", bpf_ntohl(key.sip), bpf_ntohl(key.dip));
	// bpf_printk("skb_copy_datagram_iter, found!, sport:%d, dport:%d,family:%d", key.sport, key.dport, key.family);
	// bpf_printk("skb_copy_datagram_iter, init_seq: %u, iter_type: %d", inital_seq, _(to->iter_type));

	char p_cb[8] = {0};
	BPF_CORE_READ_INTO(&p_cb, skb, cb);
	// char *p_cb = _C(skb, cb);
	struct tcp_skb_cb *cb = (struct tcp_skb_cb *)p_cb;
	//  struct tcp_skb_cb *cb = {0}; 
	// bpf_probe_read_kernel(&cb, sizeof(cb), (void*)p_cb);
	// u32 seq = (int)_C(cb,seq) + offset;
	u32 seq = 0;
	BPF_CORE_READ_INTO(&seq, cb, seq);
	seq += offset;
	struct parse_kern_evt_body body = {0};
	body.ctx = ctx;
	body.inital_seq = inital_seq;
	body.key = &key;
	body.cur_seq = seq - inital_seq;
	body.len = len;
	// body.func_name = SKB_COPY_FUNC_NAME;
	body.step = USER_COPY;
	// bpf_printk("skb_copy_datagram_iter, seq: %u, off: %u, len: %u", cb->seq, offset, len);
	parse_kern_evt_body(&body);
	// parse_skb(skb, "skb_copy_datagram_iter", 0);
	// if (_(to->iter_type) == ITER_IOVEC) {
	// 	struct iovec *iov = _(to->iov);
	// 	bpf_printk("skb_copy_datagram_iter, addr: %x, off: %x ,len: %d", _(iov->iov_base), _(to->iov_offset), _(iov->iov_len));
	// }
	return BPF_OK;
}


SEC("kprobe/__skb_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb, int offset, struct iov_iter *to, int len) {
	return handle_skb_data_copy(ctx, skb, offset, to, len);
}

SEC("kprobe/skb_copy_datagram_iovec")
int BPF_KPROBE(skb_copy_datagram_iovec, struct sk_buff *skb, int offset, struct iov_iter *to, int len) {
	return handle_skb_data_copy(ctx, skb, offset, to, len);
}


SEC("tracepoint/net/netif_receive_skb")
int tracepoint__netif_receive_skb(struct trace_event_raw_net_dev_template  *ctx) {
	void *p = (void*)ctx + sizeof(struct trace_entry);
	struct sk_buff *skb;
	bpf_probe_read_kernel(&skb, sizeof(struct sk_buff *), p);
	parse_skb(ctx, skb, 1, DEV_IN); 
	return BPF_OK;
}

SEC("kprobe/tcp_queue_rcv")
int BPF_KPROBE(tcp_queue_rcv, struct sock *sk, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_queue_rcv", 0, kTcpIn);
	return BPF_OK;
} 

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_rcv_established", 0, kTcpIn);
	return BPF_OK;
}  
  
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) { 
	parse_skb(ctx, skb, 1, TCP_IN);
	return BPF_OK;
}
 
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) {
	// parse_skb(skb, "tcp_v4_rcv", 1);
	return BPF_OK;
}

SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) {
	parse_skb(ctx, skb, 1, IP_IN);
	return BPF_OK;
} 

// 出队之后，发送到设备
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *first) {
	struct sk_buff *skb = {0};
	BPF_CORE_READ_INTO(&skb, ctx, di);
	// skb = PT_REGS_PARM1_CORE(ctx);
#pragma unroll
	for (int i = 0; i < 2; i++) {
		int ret = parse_skb(ctx, skb, 0, DEV_OUT);
		// if (ret) bpf_printk("dev_hard_start_xmit, final: %d", i);
		// skb = _C(skb,next);
		struct sk_buff *_skb = {0};
		BPF_CORE_READ_INTO(&_skb, skb, next);
		skb = _skb;
		if (!skb) {
			return 0;
		}
	}
	
	return 0;
}

// 进入qdisc之前
SEC("kprobe/dev_queue_xmit")
int BPF_KPROBE(dev_queue_xmit, struct sk_buff *skb) {
	parse_skb(ctx, skb, 0, QDISC_OUT);
	return 0;
}

static __always_inline int handle_ip_queue_xmit(void* ctx, struct sk_buff *skb)
{
	struct sock_key key = {0};
	parse_sock_key(skb, &key);
	// 如果map里有才进行后面的步骤
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (found == NULL && !should_trace_sock_key(&key)) {
		// bpf_printk("kp, lip: %d, dip:%d", key.sip, key.dip);
		return 0;
	}
	u32 inital_seq = 0;
	if (found == NULL) {
		struct tcphdr* tcp = {0};
		// struct tcphdr* tcp = (struct tcphdr*)_C(skb, data);
		BPF_CORE_READ_INTO(&tcp, skb, data);
		// inital_seq = bpf_ntohl(_C(tcp,seq)); 
		BPF_CORE_READ_INTO(&inital_seq, tcp, seq);
		inital_seq = bpf_ntohl(inital_seq);
		bpf_map_update_elem(&sock_xmit_map, &key,&inital_seq, BPF_NOEXIST);
		// bpf_printk("not found!, seq: %u", inital_seq);
	} else {
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
		// bpf_printk("found!, seq: %u", inital_seq);
	}

	struct tcphdr* tcp = {0};
	BPF_CORE_READ_INTO(&tcp, skb, data);
	// struct tcphdr* tcp = (struct tcphdr*)_C(skb, data);

	struct parse_kern_evt_body body = {0};
	body.ctx = ctx;
	body.inital_seq = inital_seq;
	body.key = &key;
	body.tcp = tcp;
	// body.len = _C(skb, len);
	BPF_CORE_READ_INTO(&body.len, skb, len);
	// body.func_name = "";
	body.step = IP_OUT;	
	report_kern_evt(&body);
	// KERN_EVENT_HANDLE(&evt, "ip_queue_xmit");
	return 0;
}


SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit2, struct sk_buff *skb)
{
	return handle_ip_queue_xmit(ctx, skb);
}


SEC("kprobe/__ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, void *sk, struct sk_buff *skb)
{
	return handle_ip_queue_xmit(ctx, skb);
}

#ifndef KERNEL_VERSION_BELOW_58
SEC("raw_tp/tcp_destroy_sock")
int BPF_PROG(tcp_destroy_sock, struct sock *sk)
{
	struct sock_key key = {0};
	// parse_sock_key_sk(sk, &key);
	const struct inet_sock *inet = (struct inet_sock *)(sk);
	parse_sock_key_sk(sk,&key);
	key.sport = bpf_ntohs(_C(inet, inet_sport));
	int err;
	err = bpf_map_delete_elem(&sock_xmit_map, &key);
	struct conn_id_s_t *conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, &key);
	uint64_t tgid_fd;
	if (conn_id_s != NULL) {
		tgid_fd = conn_id_s->tgid_fd;
		// pr_bpf_debug("tcp_destroy_sock found, tgid:%d", tgid_fd>>32);
		struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
		if (conn_info != NULL) {
			report_conn_evt(ctx, conn_info, kClose, 0);
		}
		bpf_map_delete_elem(&conn_info_map, &tgid_fd);
		bpf_map_delete_elem(&sock_key_conn_id_map, &key);
		struct sock_key rev_key = reverse_sock_key(&key);
		bpf_map_delete_elem(&sock_key_conn_id_map, &rev_key);
	} 
	if (!err) {
		// pr_bpf_debug("tcp_destroy_sock, sock destory, %d, %d", key.sport, key.dport);
	}
	return BPF_OK;
}
#endif

MY_BPF_HASH(accept_args_map, uint64_t, struct accept_args)
MY_BPF_HASH(connect_args_map, uint64_t, struct connect_args)
MY_BPF_HASH(close_args_map, uint64_t, struct close_args)
MY_BPF_HASH(write_args_map, uint64_t, struct data_args)
MY_BPF_HASH(read_args_map, uint64_t, struct data_args)
MY_BPF_HASH(enabled_remote_port_map, uint16_t, uint8_t)
MY_BPF_HASH(enabled_local_port_map, uint16_t, uint8_t)
MY_BPF_HASH(enabled_remote_ipv4_map, uint32_t, uint8_t)
MY_BPF_HASH(enabled_local_ipv4_map, uint32_t, uint8_t)


static __inline void read_sockaddr_kernel(struct conn_info_t* conn_info,
                                          const struct socket* socket) {
  // Use BPF_PROBE_READ_KERNEL_VAR since BCC cannot insert them as expected.
  struct sock* sk = _C(socket, sk);

  struct sock_common sk_common = _C(sk,__sk_common);
  uint16_t family = sk_common.skc_family;
  uint16_t lport = sk_common.skc_num;
  uint16_t rport = bpf_ntohs(sk_common.skc_dport);

  conn_info->laddr.in4.sin_family = family;
  conn_info->raddr.in4.sin_family = family;

  if (family == AF_INET) {
    conn_info->laddr.in4.sin_port = lport;
    conn_info->raddr.in4.sin_port = rport;
	conn_info->laddr.in4.sin_addr.s_addr = sk_common.skc_rcv_saddr;
	conn_info->raddr.in4.sin_addr.s_addr = sk_common.skc_daddr;
  } 
}


static __inline void init_conn_id(uint32_t tgid, int32_t fd, struct conn_id_t* conn_id) {
  conn_id->upid.tgid = tgid;
  conn_id->upid.start_time_ticks = 0;
//   conn_id->upid.start_time_ticks = get_tgid_start_time();
  conn_id->fd = fd;
  conn_id->tsid = bpf_ktime_get_ns();
}
static __inline void init_conn_info(uint32_t tgid, int32_t fd, struct conn_info_t* conn_info) {
  init_conn_id(tgid, fd, &conn_info->conn_id);
  conn_info->role = kRoleUnknown;
  conn_info->laddr.in4.sin_family = PX_AF_UNKNOWN;
  conn_info->raddr.in4.sin_family = PX_AF_UNKNOWN;
}

static __inline uint64_t gen_tgid_fd(uint32_t tgid, int fd) {
  return ((uint64_t)tgid << 32) | (uint32_t)fd;
}
static __always_inline struct tcp_sock *get_socket_from_fd(int fd_num) {
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct files_struct *files = _C(task,files);
	struct fdtable *fdt = _C(files,fdt);
	struct file **fd = _C(fdt,fd);
	void *file;
	bpf_probe_read(&file, sizeof(file), fd + fd_num);
	struct file *__file = (struct file *)file;
	void *private_data = _C(__file,private_data);
	if (private_data == NULL) {
		return NULL;
	}
	struct socket *socket = (struct socket *) private_data;
	short socket_type = _C(socket,type);
	struct file *socket_file = _C(socket,file);
	void *check_file;
	struct tcp_sock *sk;
	struct socket __socket;
	if (socket_file != file) {
		// check_file = __socket.wq;
		sk = (struct tcp_sock *)_C(socket,file);
	} else {
		check_file = _C(socket,file);
		sk = (struct tcp_sock *)_C(socket,sk);
	}
	if ((socket_type == SOCK_STREAM || socket_type == SOCK_DGRAM) 
#ifdef KERNEL_VERSION_BELOW_58
#else
	   && check_file == file /*&& __socket.state == SS_CONNECTED */
#endif
		) {
		return sk;
	}
	return NULL;
}

static __always_inline void submit_new_conn(void* ctx, uint32_t tgid, int32_t fd,
const struct sockaddr* addr, const struct socket* socket,
enum endpoint_role_t role, uint64_t start_ts) {
	struct conn_info_t conn_info = {};
	uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
	init_conn_info(tgid, fd, &conn_info);
	if (socket != NULL) {
		read_sockaddr_kernel(&conn_info, socket);
		// bpf_printk("read_sockaddr_kernel laddr: port:%u", conn_info.laddr.in4.sin_port);
		// bpf_printk("read_sockaddr_kernel raddr: port:%u", conn_info.raddr.in4.sin_port);
	} else if (addr != NULL) {
		bpf_probe_read_user(&conn_info.raddr, sizeof(union sockaddr_t), addr);
		struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
		conn_info.raddr.in4.sin_port = bpf_ntohs(conn_info.raddr.in4.sin_port);
		// conn_info.raddr = *((union sockaddr_t*)addr);
	} else {
		// pr_bpf_debug("raddr: null");
	}
	struct tcp_sock * tcp_sk = get_socket_from_fd(fd);
	// s => d
	struct sock_key key;
	if (role == kRoleClient) {
		parse_sock_key_sk((struct sock*)tcp_sk, &key);
	} else {
		parse_sock_key_rcv_sk((struct sock*)tcp_sk, &key);
	}
	
	print_sock_key(&key);
	if (socket == NULL) {
		conn_info.laddr.in4.sin_addr.s_addr = role == kRoleClient ? key.sip : key.dip;
		conn_info.laddr.in4.sin_port = role == kRoleClient ? key.sport : key.dport;
		conn_info.raddr.in4.sin_addr.s_addr = role == kRoleClient ? key.dip : key.sip;
		conn_info.raddr.in4.sin_port = role == kRoleClient ? key.dport : key.sport;
		conn_info.laddr.in4.sin_family = key.family;
		conn_info.raddr.in4.sin_family = key.family;
	}

	uint16_t one = 1;
	uint8_t* enable_local_port_filter = bpf_map_lookup_elem(&enabled_local_port_map, &one);
	if (enable_local_port_filter != NULL) {
		uint8_t* enabled_local_port = bpf_map_lookup_elem(&enabled_local_port_map, &conn_info.laddr.in4.sin_port);
		if (enabled_local_port == NULL) {
			return;
		}
	}
	uint8_t* enable_remote_port_filter = bpf_map_lookup_elem(&enabled_remote_port_map, &one);
	if (enable_remote_port_filter != NULL) {
		uint8_t* enabled_remote_port = bpf_map_lookup_elem(&enabled_remote_port_map, &conn_info.raddr.in4.sin_port);
		if (enabled_remote_port == NULL) {
			return;
		}
	}
	uint32_t one32 = 1;
	if (conn_info.raddr.in4.sin_family == AF_INET) {
		uint8_t* enable_remote_ipv4_filter = bpf_map_lookup_elem(&enabled_remote_ipv4_map, &one32);
		if (enable_remote_ipv4_filter != NULL) {
			uint8_t* enabled_remote_ipv4 = bpf_map_lookup_elem(&enabled_remote_ipv4_map, &conn_info.raddr.in4.sin_addr.s_addr);
			if (enabled_remote_ipv4 == NULL || conn_info.raddr.in4.sin_addr.s_addr == 0) {
				return;
			}
		}
	}
	// bpf_printk("submit_new_conn laddr: port:%u", conn_info.laddr.in4.sin_port);
	// bpf_printk("submit_new_conn raddr: port:%u", conn_info.raddr.in4.sin_port);

	conn_info.role = role;
	if (should_trace_conn(&conn_info)) {
		// bpf_printk("submit_new_conn  dport: %u, tgid:%d,fd:%d", conn_info.raddr.in4.sin_port,tgid ,fd);
		bpf_map_update_elem(&conn_info_map, &tgid_fd, &conn_info, BPF_ANY);
		struct conn_id_s_t conn_id_s = {};
		conn_id_s.direct = role == kRoleClient ? kEgress : kIngress;
		conn_id_s.tgid_fd = tgid_fd;
		bpf_map_update_elem(&sock_key_conn_id_map, &key, &conn_id_s, BPF_NOEXIST);
		struct sock_key rev = reverse_sock_key(&key);
		// d => s
		struct conn_id_s_t conn_id_s_rev = {};
		conn_id_s_rev.direct = role == kRoleClient ? kIngress : kEgress;
		conn_id_s_rev.tgid_fd = tgid_fd;
		bpf_map_update_elem(&sock_key_conn_id_map, &rev, &conn_id_s_rev, BPF_NOEXIST);
		report_conn_evt(ctx, &conn_info, kConnect, start_ts);
	}

}


static __always_inline void process_syscall_close(void* ctx, int ret_val, struct close_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	if (args->fd < 0) {
		// bpf_printk("close syscall args->fd:%d,tgid:%u", args->fd, tgid);
		return;
	}
	if (ret_val < 0) {
		// bpf_printk("close syscall ret_val:%d,tgid:%u", ret_val, tgid);
		return;
	}
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (conn_info == NULL) {
		// bpf_printk("close syscall no conn find,tgid:%u,fd:%d",  tgid, args->fd);
		return;
	}
	
	bool reported = report_conn_evt(ctx, conn_info, kClose, 0);
	// bpf_printk("reported  close syscall event tgid:%u , reported: %d", tgid, reported);

	bpf_map_delete_elem(&conn_info_map, &tgid_fd);
	
	struct sock_key key;
	key.sip = conn_info->laddr.in4.sin_addr.s_addr;
	key.sport = conn_info->laddr.in4.sin_port;
	key.dip = conn_info->raddr.in4.sin_addr.s_addr;
	key.dport = conn_info->raddr.in4.sin_port;
	key.family = conn_info->laddr.in4.sin_family;
	bpf_map_delete_elem(&sock_key_conn_id_map, &key);
	struct sock_key rev_key = reverse_sock_key(&key);
	bpf_map_delete_elem(&sock_key_conn_id_map, &rev_key);
}

static __always_inline void process_syscall_connect(void* ctx, int  ret_val, struct connect_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	if (ret_val < 0 && ret_val != -EINPROGRESS) {
    	return;
  	}
	if (args->fd < 0) {
		return;
	}
	if (match_trace_tgid(tgid) == TARGET_TGID_UNMATCHED) {
		return;
	}
	// bpf_printk("process_syscall_connect, tgid:%lu, fd: %d", tgid, args->fd);
	submit_new_conn(ctx, tgid, args->fd, args->addr, NULL, kRoleClient , args->start_ts);
}
static __always_inline void process_syscall_accept(void* ctx, long int ret, struct accept_args *args, uint64_t id) {
	uint32_t tgid = id >> 32;
	if (ret < 0) {
		// bpf_printk("process_syscall_accept, ret_fd: %d, socket:%d", -ret_fd,args->sock_alloc_socket);
		return;
	}

	if (match_trace_tgid(tgid) == TARGET_TGID_UNMATCHED) {
		return;
	}
	// bpf_printk("process_syscall_accept, tgid:%lu, ret_fd: %d, socket:%d", tgid,ret_fd,args->sock_alloc_socket);
	submit_new_conn(ctx, tgid, ret, args->addr, args->sock_alloc_socket, kRoleServer , 0);
}

static __always_inline void process_syscall_data_vecs(void* ctx, struct data_args *args, uint64_t id, enum traffic_direction_t direct,
	ssize_t bytes_count) {
		
	uint32_t tgid = id >> 32;
	uint64_t _tgidfd = (((uint64_t)tgid) << 32 | args->fd);
	if (args->iov == NULL) {
		return;
	}
	if (args->iovlen <= 0) {
		return;
	}
	if (args->fd < 0) {
		return;
	}
	if (bytes_count <= 0) {
		// This read()/write() call failed, or processed nothing.
		return;
	}
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (!conn_info) {
		return;
	}
	
	if (conn_info->protocol == kProtocolUnset || conn_info->protocol == kProtocolUnknown) {
		
		struct iovec iov_cpy;
		size_t buf_size = 0;
#pragma unroll
		 for (size_t i = 0; i < PROTOCOL_VEC_LIMIT && i < args->iovlen; i++) {
			bpf_probe_read_user(&iov_cpy, sizeof(iov_cpy), &args->iov[i]);
			buf_size = iov_cpy.iov_len < bytes_count ? iov_cpy.iov_len : bytes_count;
			if (buf_size != 0) {
				enum traffic_protocol_t before_infer = conn_info->protocol;
				struct protocol_message_t protocol_message = infer_protocol(iov_cpy.iov_base, buf_size, conn_info);
				if (conn_info->protocol != before_infer) {
					report_conn_evt(ctx, conn_info, kProtocolInfer, 0);
				}
				break;
			}
		 }
	} else {
	}
	
	// bpf_printk("start trace data(vecs)!, bytes_count:%d,func:%d", bytes_count, args->source_fn);		
	uint64_t seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
	struct conn_id_s_t conn_id_s;
	conn_id_s.tgid_fd = tgid_fd;
	conn_id_s.direct = direct;
	enum step_t step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
	if (should_trace_conn(conn_info)) {
		report_syscall_evt_vecs(ctx, seq, &conn_id_s, bytes_count, step, args);
	}
	
	if (direct == kEgress) {
		conn_info->write_bytes += bytes_count;
	} else {
		conn_info->read_bytes += bytes_count;
	}
}

static __always_inline void process_syscall_data(void* ctx, struct data_args *args, uint64_t id, enum traffic_direction_t direct,
	ssize_t bytes_count) {
	if (bytes_count <= 0) {
		// This read()/write() call failed, or processed nothing.
		return;
	}
	uint32_t tgid = id >> 32;
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (!conn_info) {
		return;
	} 
	if (conn_info->protocol == kProtocolUnset || conn_info->protocol == kProtocolUnknown) {
		enum traffic_protocol_t before_infer = conn_info->protocol;
		// bpf_printk("[protocol infer]:start, bc:%d", bytes_count);
		struct protocol_message_t protocol_message = infer_protocol(args->buf, bytes_count, conn_info);
		// conn_info->protocol = protocol_message.protocol;
		if (before_infer != conn_info->protocol) {
			// bpf_printk("[protocol infer]: %d", conn_info->protocol);
			report_conn_evt(ctx, conn_info, kProtocolInfer, 0);
		}
	}
	
	// bpf_printk("start trace data!, bytes_count:%d,func:%d", bytes_count, args->source_fn);
	uint64_t seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
	struct conn_id_s_t conn_id_s;
	conn_id_s.tgid_fd = tgid_fd;
	conn_id_s.direct = direct;
	enum step_t step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
	if (should_trace_conn(conn_info)) {
		report_syscall_evt(ctx, seq, &conn_id_s, bytes_count, step, args);
	}
	
	if (direct == kEgress) {
		conn_info->write_bytes += bytes_count;
	} else {
		conn_info->read_bytes += bytes_count;
	}
}

static __always_inline void process_implicit_conn(void* ctx, uint64_t id,
                                           const struct connect_args* args,
                                           enum source_function_t source_fn,
										   enum endpoint_role_t role) {
  uint32_t tgid = id >> 32;

  if (match_trace_tgid(tgid) == TARGET_TGID_UNMATCHED) {
    return;
  }

  if (args->fd < 0) {
    return;
  }

  uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);

  struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
  if (conn_info != NULL) {
    return;
  }

  submit_new_conn(ctx, tgid, args->fd, args->addr, /*socket*/ NULL, role, source_fn);
}
SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(security_socket_sendmsg_enter) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);

	if (args) {
		args->sock_event = true;
	}
	return 0;
}

SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(security_socket_recvmsg_enter) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);

	if (args) {
		args->sock_event = true;
	}
	return 0;
}

// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
//                  struct sockaddr *src_addr, socklen_t *addrlen);
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.buf, 1, ctx)
	args.source_fn = kSyscallRecvFrom;
	bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint__syscalls__sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count ;
	TP_RET(&bytes_count, ctx)

	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);
	if (args != NULL) {
		args->ts = bpf_ktime_get_ns();
		process_syscall_data(ctx, args, id, kIngress, bytes_count);
	} 

	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int tracepoint__syscalls__sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.buf, 1, ctx)
	args.source_fn = kSyscallRead;
	bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int tracepoint__syscalls__sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)
	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);
	if (args != NULL && args->sock_event) {
		args->ts = bpf_ktime_get_ns();
		process_syscall_data(ctx, args, id, kIngress, bytes_count);
	} 

	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}
struct my_user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
};

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tracepoint__syscalls__sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct my_user_msghdr* msghdr;
	TP_ARGS(&msghdr, 1, ctx)
	int sockfd ; 
	TP_ARGS(&sockfd, 0, ctx)
	if (msghdr != NULL) {
		// Stash arguments.
		void *msg_name = _U(msghdr, msg_name);
		if (msg_name != NULL) {
			struct connect_args _connect_args = {};
			_connect_args.fd = sockfd;
			_connect_args.addr = msg_name;
			bpf_map_update_elem(&connect_args_map, &id, &_connect_args, BPF_ANY);
		}

		// Stash arguments.
		struct data_args read_args = {};
		read_args.source_fn = kSyscallRecvMsg;
		read_args.fd = sockfd;
		read_args.iov = _U(msghdr, msg_iov);
		read_args.iovlen = _U(msghdr, msg_iovlen);
		bpf_map_update_elem(&read_args_map, &id, &read_args, BPF_ANY);
 	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tracepoint__syscalls__sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)

	// Unstash arguments, and process syscall.
	const struct connect_args* connect_args = bpf_map_lookup_elem(&connect_args_map, &id);
	if (connect_args != NULL && bytes_count > 0) {
		process_implicit_conn(ctx, id, connect_args, kSyscallRecvMsg, kRoleServer);
	}
	bpf_map_delete_elem(&connect_args_map, &id);

	// Unstash arguments, and process syscall.
	struct data_args* read_args = bpf_map_lookup_elem(&read_args_map, &id);
	if (read_args != NULL) {
		process_syscall_data_vecs(ctx, read_args, id, kIngress, bytes_count);
	}

	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}


SEC("tracepoint/syscalls/sys_enter_readv")
int tracepoint__syscalls__sys_enter_readv(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.iov, 1, ctx)
	TP_ARGS(&args.iovlen, 2, ctx)
	args.source_fn = kSyscallReadV;
	bpf_map_update_elem(&read_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tracepoint__syscalls__sys_exit_readv(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count ;
	TP_RET(&bytes_count, ctx)
	struct data_args *args = bpf_map_lookup_elem(&read_args_map, &id);
	if (args != NULL && args->sock_event) {
		args->ts = bpf_ktime_get_ns();
		process_syscall_data_vecs(ctx, args, id, kIngress, bytes_count);
	}
	bpf_map_delete_elem(&read_args_map, &id);
	return 0;
}


// ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
//                const struct sockaddr *dest_addr, socklen_t addrlen);
SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.buf, 1, ctx)
	args.source_fn = kSyscallSendTo;
	args.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint__syscalls__sys_exit_sendto(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL ) {
		process_syscall_data(ctx, args, id, kEgress, bytes_count);
	}

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.buf, 1, ctx)
	args.source_fn = kSyscallWrite;
	args.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int tracepoint__syscalls__sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL && args->sock_event) {
		process_syscall_data(ctx, args, id, kEgress, bytes_count);
	} 

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tracepoint__syscalls__sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct my_user_msghdr* msghdr;
	TP_ARGS(&msghdr, 1, ctx)
	int sockfd ; 
	TP_ARGS(&sockfd, 0, ctx)
	if (msghdr != NULL) {
		void *msg_name = _U(msghdr, msg_name);
		if (msg_name != NULL) {
			struct connect_args _connect_args = {};
			_connect_args.fd = sockfd;
			_connect_args.addr = msg_name;
			bpf_map_update_elem(&connect_args_map, &id, &_connect_args, BPF_ANY);
		}

	
		// Stash arguments.
		struct data_args write_args = {};
		write_args.fd = sockfd;
		write_args.iov = _U(msghdr, msg_iov);
		write_args.iovlen = _U(msghdr, msg_iovlen);
		write_args.source_fn = kSyscallSendMsg;
		bpf_map_update_elem(&write_args_map, &id, &write_args, BPF_ANY);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int tracepoint__syscalls__sys_exit_sendmsg(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)

	const struct connect_args* _connect_args = bpf_map_lookup_elem(&connect_args_map, &id);
	if (_connect_args != NULL && bytes_count > 0) {
		process_implicit_conn(ctx, id, _connect_args, kSyscallSendMsg, kRoleClient);
	}
	bpf_map_delete_elem(&connect_args_map, &id);

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL) {
		process_syscall_data_vecs(ctx, args, id, kEgress, bytes_count);
	} 

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}


SEC("tracepoint/syscalls/sys_enter_writev")
int tracepoint__syscalls__sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct data_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.iov, 1, ctx)
	TP_ARGS(&args.iovlen, 2, ctx)
	args.source_fn = kSyscallWriteV;
	args.ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&write_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tracepoint__syscalls__sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	ssize_t bytes_count;
	TP_RET(&bytes_count, ctx)

	struct data_args *args = bpf_map_lookup_elem(&write_args_map, &id);
	if (args != NULL && args->sock_event) {
		process_syscall_data_vecs(ctx, args, id, kEgress, bytes_count);
	}

	bpf_map_delete_elem(&write_args_map, &id);
	return 0;
}

// int close(int fd);
SEC("tracepoint/syscalls/sys_enter_close")
// SEC("kprobe/sys_close")
int tracepoint__syscalls__sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct close_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	bpf_map_update_elem(&close_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct trace_event_raw_sys_exit *ctx)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct close_args *args = bpf_map_lookup_elem(&close_args_map, &id);
	if (args != NULL) {
		long int ret;
		TP_RET(&ret, ctx);
		process_syscall_close(ctx, ret, args, id);
	}	
	bpf_map_delete_elem(&close_args_map, &id);
	return 0;
}


//int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct connect_args args = {0};
	TP_ARGS(&args.fd, 0, ctx)
	TP_ARGS(&args.addr, 1, ctx)
	args.start_ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&connect_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct connect_args *args = bpf_map_lookup_elem(&connect_args_map, &id);

	if (args != NULL) {
		long int ret;
		TP_RET(&ret, ctx);
		process_syscall_connect(ctx, ret, args, id);
	} 
	bpf_map_delete_elem(&connect_args_map, &id);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int tracepoint__syscalls__sys_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();

	struct accept_args args = {0};
	TP_ARGS(&args.addr, 1, ctx)
	bpf_map_update_elem(&accept_args_map, &id, &args, BPF_ANY);
	return 0;
}

SEC("kretprobe/sock_alloc") 
int BPF_KRETPROBE(sock_alloc_ret)
{
	uint64_t id = bpf_get_current_pid_tgid();
	struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &id);
	if (!args) {
		return 0;
	}
	if (!args->sock_alloc_socket) {
		struct socket *sk = {0};
		BPF_CORE_READ_INTO(&sk, ctx, ax);
		// args->sock_alloc_socket = (struct socket*) PT_REGS_RC_CORE(ctx);
		args->sock_alloc_socket = sk;
	}

	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct trace_event_raw_sys_exit *ctx) {
	uint64_t id = bpf_get_current_pid_tgid();
	struct accept_args *args = bpf_map_lookup_elem(&accept_args_map, &id);

	if (args != NULL) {
		long int ret;
		TP_RET(&ret, ctx);
		process_syscall_accept(ctx, ret, args, id);
	} 
	bpf_map_delete_elem(&accept_args_map, &id);
	return 0;
}
