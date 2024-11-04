//go:build ignore

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
// #include "../vmlinux/vmlinux.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>
#include "pktlatency.h"
#include "protocol_inference.h"
#include "data_common.h"
#include "go_common.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";

const struct in6_addr *in6_addr_unused __attribute__((unused));
const struct kern_evt *kern_evt_unused __attribute__((unused));
const struct kern_evt_ssl_data *kern_evt_ssl_data_unused __attribute__((unused));
const struct conn_evt_t *conn_evt_t_unused __attribute__((unused));
const struct sock_key *sock_key_unused __attribute__((unused));
const struct kern_evt_data *kern_evt_data_unused __attribute__((unused));
const struct conn_id_s_t *conn_id_s_t_unused __attribute__((unused));
const struct conn_info_t *conn_info_t_unused __attribute__((unused));
const struct process_exec_event *process_exec_event_unused __attribute__((unused));
const struct process_exit_event *process_exit_event_unused __attribute__((unused));
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct sock_key));
	__uint(value_size, sizeof(struct sock_key));
	__uint(max_entries, 65535);
	__uint(map_flags, 0);
} nat_flow_map SEC(".maps");

MY_BPF_ARRAY_PERCPU(conn_info_t_map, struct conn_info_t)
MY_BPF_ARRAY_PERCPU(kern_evt_t_map, struct kern_evt)


MY_BPF_HASH(control_values, uint32_t, int64_t)

enum target_tgid_match_result_t {
  TARGET_TGID_UNSPECIFIED,
  TARGET_TGID_ALL,
  TARGET_TGID_MATCHED,
  TARGET_TGID_UNMATCHED,
};

static __always_inline int filter_mntns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_mntns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_pidns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_pidns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline int filter_netns(u32 ns) {
    if (bpf_map_lookup_elem(&filter_netns_map, &ns)) {
        return 0;
    }
    return -1;
}

static __always_inline enum target_tgid_match_result_t match_trace_tgid(const uint32_t tgid) {
	uint32_t idx = kEnableFilterByPid;
	int64_t* target_tgid = bpf_map_lookup_elem(&control_values, &idx);
	if (target_tgid == NULL) {
		return TARGET_TGID_ALL;
	}
	if (bpf_map_lookup_elem(&filter_pid_map, &tgid)) {
		return TARGET_TGID_MATCHED;
	}
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	uint32_t parent_tgid = BPF_CORE_READ(parent, tgid);
	if (parent && bpf_map_lookup_elem(&filter_pid_map, &parent_tgid)) {
    	u8 u8_zero = 0;
        bpf_map_update_elem(&filter_pid_map, &tgid, &u8_zero, BPF_NOEXIST);
		return TARGET_TGID_MATCHED;
	}
#ifdef LAGACY_KERNEL_310

	return TARGET_TGID_UNMATCHED;
#else

    bool should_filter = false;
    u32 pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    u32 netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    if ((filter_pidns(pidns_id) == 0) || (filter_mntns(mntns_id) == 0) || (filter_netns(netns_id) == 0)) {
        should_filter = true;
    }
	if (should_filter) {
    	u8 u8_zero = 0;
        bpf_map_update_elem(&filter_pid_map, &tgid, &u8_zero, BPF_NOEXIST);
		return TARGET_TGID_MATCHED;
	}

	return TARGET_TGID_UNMATCHED;
#endif
}

static __always_inline void reverse_sock_key_no_copy(struct sock_key* key) {
	uint64_t temp = key->sip[0];
	key->sip[0] = key->dip[0];
	key->dip[0] = temp;
	temp = key->sip[1];
	key->sip[1] = key->dip[1];
	key->dip[1] = temp;
	temp = key->sport;
	key->sport = key->dport;
	key->dport = temp;
}
static void __always_inline print_sock_key(struct sock_key* key) {
	// bpf_printk("print_sock_key port: sport:%u, dport:%u\n", key->sport, key->dport);
	// bpf_printk("print_sock_key addr: saddr:%llx, saddr:%llx\n", key->sip[0], key->sip[1]);
	// bpf_printk("print_sock_key addr: daddr:%llx, daddr:%llx\n", key->dip[0], key->dip[1]);
	// bpf_printk("print_sock_key family: family:%u", key->family);
}
static void __always_inline parse_kern_evt_body(struct parse_kern_evt_body *param) {
	void* ctx = param->ctx;
	u32 inital_seq = param->inital_seq;
	struct sock_key *key = param->key;
	u32 cur_seq = param->cur_seq;
	u32 len = param->len;
	const char *func_name = param->func_name;
	enum step_t step = param->step;
	int zero = 0;
	struct kern_evt* evt = bpf_map_lookup_elem(&kern_evt_t_map, &zero);
	if(!evt) {
		return;
	}
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
 
	if (conn_id_s == NULL || conn_id_s->no_trace) {
		return;
	}
	uint64_t tgid_fd = conn_id_s->tgid_fd;
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (conn_info == NULL || conn_info->protocol == kProtocolUnknown) {
		return;
	}

	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	evt->seq = cur_seq; 
	// u32 doff = BPF_CORE_READ_BITFIELD_PROBED(tcp, doff);
	// u64 hdr_len = doff << 2;
	evt->len = len; 
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	bpf_probe_read_kernel(evt->func_name,FUNC_NAME_LIMIT, func_name);
	// my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);
	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, evt, sizeof(struct kern_evt));
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
	// struct kern_evt _evt = {0};
	// struct kern_evt* evt = &_evt;

	int zero = 0;
	struct kern_evt* evt = bpf_map_lookup_elem(&kern_evt_t_map, &zero);
	if(!evt) {
		return;
	}
	struct conn_id_s_t* conn_id_s = bpf_map_lookup_elem(&sock_key_conn_id_map, key);
 
	if (conn_id_s == NULL || conn_id_s->no_trace) {
		// if (key->sport==3306&& step == DEV_IN) {
		// 	bpf_printk("discard!");
		// 	print_sock_key(key);
		// }
		return;
	}
	uint64_t tgid_fd = conn_id_s->tgid_fd;
	struct conn_info_t *conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	if (conn_info == NULL || conn_info->protocol == kProtocolUnknown) {
		return;
	}

	bpf_core_read(&evt->conn_id_s, sizeof(struct conn_id_s_t), conn_id_s);
	u32 tcpseq = 0;
	BPF_CORE_READ_INTO(&tcpseq, tcp, seq);
	tcpseq  = bpf_htonl(tcpseq);
	evt->seq = (uint64_t)(tcpseq - seq); 
	// evt->tcp_seq = bpf_ntohl(_(tcp->seq));
	u32 doff = 0;
	bpf_probe_read_kernel(&doff, sizeof(doff), (void*)tcp + 12);
	doff = (doff&255) >> 4;
	u64 hdr_len = doff << 2;
	evt->len = len - hdr_len;
	evt->ts = bpf_ktime_get_ns();
	evt->step = step;
	evt->ifindex = param->ifindex;
	// evt->flags = _(((u8 *)tcp)[13]);
	bpf_probe_read_kernel(&evt->flags, sizeof(uint8_t), &(((u8 *)tcp)[13]));
	// bpf_probe_read_kernel(evt->func_name,FUNC_NAME_LIMIT, func_name);
	// my_strcpy(evt->func_name, func_name, FUNC_NAME_LIMIT);

	bpf_perf_event_output(ctx, &rb, BPF_F_CURRENT_CPU, evt, sizeof(struct kern_evt));
}

#define DEBUG 0

static bool __always_inline use_ipv6(struct sock_common * skc) {
	bool use = true;
	use = use && bpf_core_field_exists(struct sock_common, skc_v6_daddr);
	if (!use) {
		return false;
	}
	use = use && bpf_core_field_exists(struct sock_common, skc_state);
	if (!use) {
		return false;
	}
	int8_t flag = -1;
	int onlyIpv6 = 0;
	int offset = bpf_core_field_offset(struct sock_common,skc_state );
	if (offset > 0) {
		bpf_probe_read_kernel(&flag, 1, (void*)skc + offset + 1); // flag = 01[0]0 0001
		if (flag != -1) {
			onlyIpv6 = flag & (1<<5);
		} 
		// onlyIpv6 = BPF_CORE_READ_BITFIELD_PROBED(skc, skc_ipv6only);
	}
	use = use && onlyIpv6;
	return use;
}
static bool __always_inline parse_sock_key_sk(struct sock* sk, struct sock_key* key) {
	struct sock_common *skc = {0};
	skc = (struct sock_common *)sk;
	bool supportIpv6 = use_ipv6(skc);
	switch (_C(skc, skc_family)) {
		case AF_INET: 
			key->dip[0] = _C(skc, skc_daddr);
			key->sip[0] = _C(skc, skc_rcv_saddr);
			break;
		case AF_INET6:
			if (supportIpv6) {
				bpf_probe_read_kernel((void *)(key->dip), sizeof(struct in6_addr), (const void *)__builtin_preserve_access_index(&((typeof((skc)))((skc)))->skc_v6_daddr)); 
				bpf_probe_read_kernel((void *)(key->sip), sizeof(struct in6_addr), (const void *)__builtin_preserve_access_index(&((typeof((skc)))((skc)))->skc_v6_rcv_saddr));
			} else {
				key->dip[0] = _C(skc, skc_daddr);
				key->sip[0] = _C(skc, skc_rcv_saddr);
			}
		break;
		default:
			return false;
	}
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&sport,sk,__sk_common.skc_num);
	BPF_CORE_READ_INTO(&dport,sk,__sk_common.skc_dport);
	dport = bpf_ntohs(dport);
	key->dport = dport;
	key->sport = sport;
	return true;
}
static bool __always_inline parse_sock_key_rcv_sk(struct sock* sk, struct sock_key* key) {
	parse_sock_key_sk(sk, key);
	reverse_sock_key_no_copy(key);
	return true;
}
static  __always_inline bool parse_sock_key_rcv(struct sk_buff *skb, struct sock_key* key) {
	struct sock* sk = {0};
	BPF_CORE_READ_INTO(&sk, skb, sk);
	return parse_sock_key_rcv_sk(sk, key);
}
static void __always_inline parse_sock_key(struct sk_buff *skb, struct sock_key* key) {

	struct sock* _sk = {0};
	BPF_CORE_READ_INTO(&_sk,skb,sk);
	parse_sock_key_sk(_sk, key);
}

static void __always_inline parse_sock_key_from_ipv4_tcp_hdr(struct sock_key *key, struct iphdr *ipv4, 
	struct tcphdr *tcp) {
	u32 saddr = 0;
	u32 daddr = 0;
	BPF_CORE_READ_INTO(&saddr, ipv4, saddr);
	BPF_CORE_READ_INTO(&daddr, ipv4, daddr);
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&sport, tcp, source);
	BPF_CORE_READ_INTO(&dport, tcp, dest);
	key->sip[0] = saddr;
	key->dip[0] = daddr;
	key->sport = bpf_ntohs(sport);
	key->dport = bpf_ntohs(dport);
}

static void __always_inline parse_sock_key_from_ipv6_tcp_hdr(struct sock_key *key, struct ipv6hdr *ipv6, 
	struct tcphdr *tcp) {
	// BPF_CORE_READ_INTO(key->sip, ipv6, saddr);
	// BPF_CORE_READ_INTO(key->dip, ipv6, daddr);
	bpf_probe_read_kernel((void *)(key->sip), 16, (const void *)__builtin_preserve_access_index(&((typeof((ipv6)))((ipv6)))->saddr)); 
	bpf_probe_read_kernel((void *)(key->dip), 16, (const void *)__builtin_preserve_access_index(&((typeof((ipv6)))((ipv6)))->daddr)); 
	u16 sport = 0;
	u16 dport = 0;
	BPF_CORE_READ_INTO(&sport, tcp, source);
	BPF_CORE_READ_INTO(&dport, tcp, dest);
	key->sport = bpf_ntohs(sport);
	key->dport = bpf_ntohs(dport);
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
	u16 l3_proto;
	if (is_l2) {
		goto __l2;
	} else {
		u16 _protocol = 0;
		BPF_CORE_READ_INTO(&_protocol, skb, protocol);
		l3_proto = bpf_ntohs(_protocol);
		// bpf_printk("%s, l3_proto: %x", func_name, l3_proto);
		if (l3_proto == ETH_P_IP || l3_proto == ETH_P_IPV6) {
			// bpf_printk("%s, is_ip: %d", func_name, 1);
			l3 = data + network_header;
			goto __l3;
		} else if (mac_header >= network_header) {
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
		BPF_CORE_READ_INTO(&l3_proto, eth, h_proto);
		l3_proto = bpf_ntohs(l3_proto);
		// bpf_printk("%s, l3_proto: %x",func_name, l3_proto);
		if (l3_proto == ETH_P_IP || l3_proto == ETH_P_IPV6) {
	__l3:	
			if (!skb_l4_check(trans_header, network_header)) {
				// 存在l4
				// bpf_printk("%s, skb_l4_check: %d",func_name, 0);
				l4 = data + trans_header;
			}
			// output: *ip, tcp_len, proto_l4, l4
			struct iphdr *ipv4 = ip;
			struct ipv6hdr *ipv6 = ip;
			u32 tcp_len;
			u8 proto_l4 = 0;
			if (l3_proto == ETH_P_IP)
			{
				u16 tot_len16 = 0;
				BPF_CORE_READ_INTO(&tot_len16, ipv4, tot_len);
				u32 len  = bpf_ntohs(tot_len16);
				u8 ip_hdr_len = 0;
				bpf_probe_read_kernel(&ip_hdr_len, sizeof(((u8 *)ip)[0]), &(((u8 *)ip)[0]));
				ip_hdr_len = get_ip_header_len(ip_hdr_len); 
				l4 = l4 ? l4 : ip + ip_hdr_len;
				BPF_CORE_READ_INTO(&proto_l4, ipv4, protocol);
				tcp_len = len - ip_hdr_len;
			} else if (l3_proto == ETH_P_IPV6) {
				proto_l4 = _(ipv6->nexthdr);
				tcp_len = _C(ipv6, payload_len);
				l4 = l4 ? l4 : ip + sizeof(*ipv6);
			}else{
				goto err;
			}
			
			struct tcphdr *tcp = l4;
			if (proto_l4 == IPPROTO_TCP) {
				if (!inital_seq) {
					// 在这里补充sk
					if (l3_proto == ETH_P_IP) {
						parse_sock_key_from_ipv4_tcp_hdr(&key, ipv4, tcp);
					}else{
						parse_sock_key_from_ipv6_tcp_hdr(&key, ipv6, tcp);
					}
					if (step == DEV_IN || step == DEV_OUT) {
						struct sock_key *translated_flow = bpf_map_lookup_elem(&nat_flow_map, &key);
						if (translated_flow != NULL) {
							key = *translated_flow;
						}
					}
					// if (key.dport != target_port && key.sport != target_port) {
					// 	goto err;
					// }
					// if (!should_trace_sock_key(&key)) {
					// 	goto err;
					// }
					int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
					if (found == NULL) {
						if (step == DEV_IN) {
							BPF_CORE_READ_INTO(&inital_seq, tcp, seq);
							inital_seq = bpf_ntohl(inital_seq);
							uint8_t flag = 0;
							bpf_probe_read_kernel(&flag, sizeof(uint8_t), &(((u8 *)tcp)[13]));
							if ((flag & (1 << 1)) == 0) {
								inital_seq--;
							}
							bpf_map_update_elem(&sock_xmit_map, &key, &inital_seq, BPF_NOEXIST);
						} else {
							goto err;
						}
						// goto err;
					} else {
						bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
					}
				} 
				struct parse_kern_evt_body body = {0};
				body.ctx = ctx;
				body.inital_seq = inital_seq;
				body.key = &key;
				body.tcp = tcp;
				body.len = tcp_len;
				// body.func_name = func_name;
				body.step = step;	

				struct net_device *dev = _C(skb, dev);
				if (dev) {
					body.ifindex = _C(dev, ifindex);
				} else {
					body.ifindex = _C(skb, skb_iif);
				}
				if (step >= NIC_IN){
					reverse_sock_key_no_copy(&key);
				}
				report_kern_evt(&body);
				return 1;
			} else {
				// bpf_printk("%s, not match: %d", func_name, _C(ipv4,saddr));
			}
		}
	}
	err:return BPF_OK;
}

SEC("xdp")
int xdp_proxy(struct xdp_md *ctx){
	return XDP_PASS;
}

static __always_inline int handle_skb_data_copy(void *ctx, struct sk_buff *skb, int offset, struct iov_iter *to, int len) {
	struct sock_key key = {0};
	parse_sock_key_rcv(skb, &key);
	int  *found = bpf_map_lookup_elem(&sock_xmit_map, &key);
	if (!found) {
		return BPF_OK;
	}
	// if (!should_trace_sock_key(&key)) {
	// 	return BPF_OK;
	// }
	u32 inital_seq = 0;
	bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);

	char* p_cb = _C(skb,cb);
	struct tcp_skb_cb *cb = (struct tcp_skb_cb *)&p_cb[0];
	u32 seq = _C(cb,seq) + offset;

	reverse_sock_key_no_copy(&key);

	struct parse_kern_evt_body body = {0};
	body.ctx = ctx;
	body.inital_seq = inital_seq;
	body.key = &key;
	body.cur_seq = seq - inital_seq;
	body.len = len;
	// body.func_name = SKB_COPY_FUNC_NAME;
	body.step = USER_COPY;
	parse_kern_evt_body(&body);
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
#ifdef ARCH_amd64
	BPF_CORE_READ_INTO(&skb, ctx, di);
#else
    skb = PT_REGS_PARM1_CORE(ctx);
#endif
	// BPF_CORE_READ_INTO(&skb, ctx, di);
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
	if (found == NULL) {
		return 0;
	}
	u32 inital_seq = 0;
	struct tcphdr* tcp = {0};
	BPF_CORE_READ_INTO(&tcp, skb, data);
	if (found == NULL) {
		return 0;
	} else {
		bpf_probe_read_kernel(&inital_seq, sizeof(inital_seq), found);
	}

	struct parse_kern_evt_body body = {0};
	body.ctx = ctx;
	body.inital_seq = inital_seq;
	body.key = &key;
	body.tcp = tcp;
	BPF_CORE_READ_INTO(&body.len, skb, len);
	// body.func_name = "";
	body.step = IP_OUT;	
	report_kern_evt(&body);
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
	} 
	if (!err) {
		// pr_bpf_debug("tcp_destroy_sock, sock destory, %d, %d", key.sport, key.dport);
	}
	return BPF_OK;
}
// #endif

// nat

static __always_inline void parse_conntrack_tuple(struct nf_conntrack_tuple *tuple, struct sock_key *flow) {
    BPF_CORE_READ_INTO(&flow->sip, tuple, src.u3.all);
    BPF_CORE_READ_INTO(&flow->dip, tuple, dst.u3.all);

    flow->sport = bpf_ntohs(tuple->src.u.all);
    flow->dport = bpf_ntohs(tuple->dst.u.all);
}
static __always_inline void reverse_flow(struct sock_key *orig_flow, struct sock_key *new_flow) {
    new_flow->sip[0] = orig_flow->dip[0];
    new_flow->sip[1] = orig_flow->dip[1];

    new_flow->dip[0] = orig_flow->sip[0];
    new_flow->dip[1] = orig_flow->sip[1];

    new_flow->sport = orig_flow->dport;
    new_flow->dport = orig_flow->sport;
}

static __always_inline void handle_nat(struct nf_conn *ct) {
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];

    if (bpf_core_field_exists(ct->tuplehash)) {
        BPF_CORE_READ_INTO(&tuplehash, ct, tuplehash);
    } else {
        struct nf_conn___older_52 *nf_conn_old = (void *)ct;
        if (bpf_core_field_exists(nf_conn_old->tuplehash)) {
            BPF_CORE_READ_INTO(&tuplehash, nf_conn_old, tuplehash);
        } else {
            return;
        }
    }

    struct nf_conntrack_tuple *orig_tuple = &tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple *reply_tuple = &tuplehash[IP_CT_DIR_REPLY].tuple;

    struct sock_key orig = {0};
    struct sock_key reply = {0};
    parse_conntrack_tuple(orig_tuple, &orig);
    parse_conntrack_tuple(reply_tuple, &reply);

    struct sock_key reversed_orig = {0};
    reverse_flow(&orig, &reversed_orig);
    // debug_log("[ptcpdump] nat flow %pI4:%d %pI4:%d ->\n",
    // 		&reply.saddr[0], reply.sport,
    // 	       	&reply.daddr[0], reply.dport);
    // debug_log("[ptcpdump]                               -> %pI4:%d %pI4:%d\n",
    // 		&reversed_orig.saddr[0], reversed_orig.sport,
    // 		&reversed_orig.saddr[0], reversed_orig.dport);
    bpf_map_update_elem(&nat_flow_map, &reply, &reversed_orig, BPF_ANY);

    struct sock_key reversed_reply = {0};
    reverse_flow(&reply, &reversed_reply);
    // debug_log("[ptcpdump] nat flow %pI4:%d %pI4:%d ->\n",
    // 		&reversed_reply.saddr[0], reversed_reply.sport,
    // 	       	&reversed_reply.daddr[0], reversed_reply.dport);
    // debug_log("[ptcpdump]                               -> %pI4:%d %pI4:%d\n",
    // 		&orig.saddr[0], orig.sport,
    // 		&orig.saddr[0], orig.dport);
    bpf_map_update_elem(&nat_flow_map, &reversed_reply, &orig, BPF_ANY);
}

SEC("kprobe/nf_nat_packet")
int BPF_KPROBE(kprobe__nf_nat_packet, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(kprobe__nf_nat_manip_pkt, void *_, struct nf_conn *ct) {
    handle_nat(ct);
    return 0;
}

MY_BPF_HASH(accept_args_map, uint64_t, struct accept_args)
MY_BPF_HASH(connect_args_map, uint64_t, struct connect_args)
MY_BPF_HASH(close_args_map, uint64_t, struct close_args)
MY_BPF_HASH(write_args_map, uint64_t, struct data_args)
MY_BPF_HASH(read_args_map, uint64_t, struct data_args)
MY_BPF_HASH(enabled_remote_port_map, uint16_t, uint8_t)
MY_BPF_HASH(enabled_local_port_map, uint16_t, uint8_t)
MY_BPF_HASH(enabled_remote_ip_map, struct in6_addr , uint8_t)
MY_BPF_HASH(enabled_local_ipv4_map, uint32_t, uint8_t)


static __inline void read_sockaddr_kernel(struct conn_info_t* conn_info,
                                          const struct socket* socket) {
  // Use BPF_PROBE_READ_KERNEL_VAR since BCC cannot insert them as expected.
  struct sock* sk = _C(socket, sk);

  struct sock_common *sk_common = &sk->__sk_common; // 这里不行可以直接强转

  uint16_t family = -1;
  uint16_t lport = -1;
  uint16_t rport = -1;
  BPF_CORE_READ_INTO(&family, sk_common, skc_family);
  BPF_CORE_READ_INTO(&lport, sk_common, skc_num);
  BPF_CORE_READ_INTO(&rport, sk_common, skc_dport);
  rport = bpf_ntohs(rport);

  conn_info->laddr.sa.sa_family = family;
  conn_info->raddr.sa.sa_family = family;

	conn_info->laddr.in6.sin6_port = lport;
	conn_info->raddr.in6.sin6_port = rport;
  if (family == AF_INET || !use_ipv6(sk_common)) {
	conn_info->laddr.in6.sin6_addr.in6_u.u6_addr32[0] = _C(sk_common, skc_rcv_saddr);
	conn_info->raddr.in6.sin6_addr.in6_u.u6_addr32[0] = _C(sk_common, skc_daddr);
	// BPF_CORE_READ_INTO(&conn_info->laddr.in4.sin_addr.s_addr, sk_common, skc_rcv_saddr);
	// BPF_CORE_READ_INTO(&conn_info->raddr.in4.sin_addr.s_addr, sk_common, skc_daddr);
  } else if (family == AF_INET6) {
	BPF_CORE_READ_INTO(&conn_info->laddr.in6.sin6_addr, sk_common, skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(&conn_info->raddr.in6.sin6_addr, sk_common, skc_v6_daddr);
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
  conn_info->laddr.in6.sin6_family = PX_AF_UNKNOWN;
  conn_info->raddr.in6.sin6_family = PX_AF_UNKNOWN;
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
// #ifdef KERNEL_VERSION_BELOW_58
// #else
// 	   && check_file == file /*&& __socket.state == SS_CONNECTED */
// #endif
		) {
		return sk;
	}
	return NULL;
}
static  __always_inline bool filter_conn_info(struct conn_info_t *conn_info) {
	if (conn_info->role != kRoleUnknown) {
		uint32_t idx = kSideFilter;
		uint64_t* side_filter_p = bpf_map_lookup_elem(&control_values, &idx);
		if (side_filter_p != NULL && *side_filter_p != 0) {
			if ((*side_filter_p == 1) != (conn_info->role==kRoleServer)) {
				return false;
			}
		}
	}

	uint16_t one = 1;
	uint8_t* enable_local_port_filter = bpf_map_lookup_elem(&enabled_local_port_map, &one);
	if (enable_local_port_filter != NULL) {
		u16 port = conn_info->laddr.in6.sin6_port;
		uint8_t* enabled_local_port = bpf_map_lookup_elem(&enabled_local_port_map, &port);
		if (enabled_local_port == NULL) {
			return false;
		}
	}
	uint8_t* enable_remote_port_filter = bpf_map_lookup_elem(&enabled_remote_port_map, &one);
	if (enable_remote_port_filter != NULL) {
		u16 port = conn_info->raddr.in6.sin6_port;
		uint8_t* enabled_remote_port = bpf_map_lookup_elem(&enabled_remote_port_map, &port);
		if (enabled_remote_port == NULL) {
			return false;
		}
	}
	uint32_t one32 = 1;
	struct in6_addr test = {0};
	test.in6_u.u6_addr8[0] = 1;
	uint8_t* enable_remote_ipv4_filter = bpf_map_lookup_elem(&enabled_remote_ip_map, &test);
	if (enable_remote_ipv4_filter != NULL) {
		test.in6_u.u6_addr8[0] = 0;
		test = conn_info->raddr.in6.sin6_addr;
		// test.in6_u.u6_addr32[0] = conn_info->raddr.in6.sin6_addr.in6_u.u6_addr32[0];
		uint8_t* enabled_remote_ipv4 = bpf_map_lookup_elem(&enabled_remote_ip_map, &test);
		if (enabled_remote_ipv4 == NULL) {
			return false;
		}
	}
	return true;
}
static __always_inline bool create_conn_info(void* ctx, struct conn_info_t *conn_info, uint64_t tgid_fd, const struct sock_key *key, enum endpoint_role_t role, uint64_t start_ts) {
	if (should_trace_conn(conn_info) && filter_conn_info(conn_info) && conn_info->laddr.in6.sin6_port != 0) {
		
		bpf_map_update_elem(&conn_info_map, &tgid_fd, conn_info, BPF_ANY);
		struct conn_id_s_t conn_id_s = {};
		conn_id_s.tgid_fd = tgid_fd;
		bpf_map_update_elem(&sock_key_conn_id_map, key, &conn_id_s, BPF_NOEXIST);
		report_conn_evt(ctx, conn_info, kConnect, start_ts);
		return true;
	} else {
		return false;
	}
}

static __always_inline void submit_new_conn(void* ctx, uint32_t tgid, int32_t fd,
const struct sockaddr* addr, const struct socket* socket,
enum endpoint_role_t role, uint64_t start_ts) {
	struct conn_info_t conn_info = {0};
	uint64_t tgid_fd = gen_tgid_fd(tgid, fd);
	init_conn_info(tgid, fd, &conn_info);
	if (socket != NULL) {
		read_sockaddr_kernel(&conn_info, socket);
		// bpf_printk("read_sockaddr_kernel laddr: port:%u", conn_info.laddr.in4.sin_port);
		// bpf_printk("read_sockaddr_kernel raddr: port:%u", conn_info.raddr.in4.sin_port);
	} else if (addr != NULL) {
		// bpf_probe_read_user(&conn_info.raddr, sizeof(union sockaddr_t), addr);
		// struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
		// conn_info.raddr.in6.sin6_port = bpf_ntohs(conn_info.raddr.in6.sin6_port);
		// conn_info.raddr = *((union sockaddr_t*)addr);
	} else {
		// pr_bpf_debug("raddr: null");
	}
	struct tcp_sock * tcp_sk = get_socket_from_fd(fd);
	if (!tcp_sk) {
		tcp_sk = (struct tcp_sock *) _C(socket, sk);
	}
	// s => d
	struct sock_key key = {0};
	parse_sock_key_sk((struct sock*)tcp_sk, &key);
	// if (role == kRoleClient) {
	// 	parse_sock_key_sk((struct sock*)tcp_sk, &key);
	// } else {
	// 	parse_sock_key_rcv_sk((struct sock*)tcp_sk, &key);
	// }
	
	// print_sock_key(&key);
	struct sock_common *sk_common = (struct sock_common *) tcp_sk; 
	bool is_ipv6 = use_ipv6(sk_common);
	if (socket == NULL) {
		// conn_info.laddr.in4.sin_addr.s_addr = role == kRoleClient ? key.sip : key.dip;
		// conn_info.laddr.in4.sin_port = role == kRoleClient ? key.sport : key.dport;
		// conn_info.raddr.in4.sin_addr.s_addr = role == kRoleClient ? key.dip : key.sip;
		// conn_info.raddr.in4.sin_port = role == kRoleClient ? key.dport : key.sport;
		// conn_info.laddr.in4.sin_family = key.family;
		// conn_info.raddr.in4.sin_family = key.family;
		conn_info.laddr.in6.sin6_port =  key.sport ;
		conn_info.raddr.in6.sin6_port = key.dport;
		uint16_t family = -1;
		BPF_CORE_READ_INTO(&family, sk_common, skc_family);
	// bpf_printk("AF: %d", family);
		if (family == AF_INET || !is_ipv6) {
			// conn_info.laddr.in4.sin_addr.s_addr = (u32)key.sip[0] ;
			// conn_info.raddr.in4.sin_addr.s_addr = (u32)key.dip[0];
			conn_info.laddr.in6.sin6_addr.in6_u.u6_addr32[0] = (u32)key.sip[0];
			conn_info.raddr.in6.sin6_addr.in6_u.u6_addr32[0] = (u32)key.dip[0];
		} else if (family == AF_INET6) {
			bpf_probe_read_kernel(&conn_info.laddr.in6.sin6_addr, sizeof(struct in6_addr), key.sip);
			bpf_probe_read_kernel(&conn_info.raddr.in6.sin6_addr, sizeof(struct in6_addr), key.dip);
		}
		conn_info.laddr.sa.sa_family = family;
		conn_info.raddr.sa.sa_family = family;
	}
	if (!use_ipv6(sk_common)) {
		conn_info.laddr.sa.sa_family = AF_INET;
		conn_info.raddr.sa.sa_family = AF_INET;
	}

	// bpf_printk("submit_new_conn laddr: port:%u", conn_info.laddr.in4.sin_port);
	// bpf_printk("submit_new_conn raddr: port:%u", conn_info.raddr.in4.sin_port);

	conn_info.role = role;

	bool created = create_conn_info(ctx, &conn_info, tgid_fd, &key, role, start_ts);
	if (created && tcp_sk) {
		// parse_sock_key_sk((struct sock*)tcp_sk, &key);
		u32 write_seq = _C(tcp_sk,write_seq);
		u32 copied_seq = _C(tcp_sk, copied_seq);
		if (write_seq != 0) {
			write_seq--;
			bpf_map_update_elem(&sock_xmit_map, &key, &write_seq, BPF_ANY);
		}
		parse_sock_key_rcv_sk((struct sock*)tcp_sk, &key);
		if (copied_seq != 0) {
			copied_seq--;
			bpf_map_update_elem(&sock_xmit_map, &key, &copied_seq, BPF_ANY);
		}
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
	
	struct sock_key key = {0};
	key.sport = conn_info->laddr.in6.sin6_port;
	key.dport = conn_info->raddr.in6.sin6_port;
	if (conn_info->laddr.sa.sa_family == AF_INET) {
		key.sip[0] = conn_info->laddr.in6.sin6_addr.in6_u.u6_addr32[0];
		key.dip[0] = conn_info->raddr.in6.sin6_addr.in6_u.u6_addr32[0];
	} else {
		bpf_probe_read_kernel(key.sip, 16, &conn_info->laddr.in6.sin6_addr);
		bpf_probe_read_kernel(key.dip, 16, &conn_info->raddr.in6.sin6_addr);
	}
	bpf_map_delete_elem(&sock_key_conn_id_map, &key);
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



static __always_inline bool create_conn_info_in_data_syscall(void* ctx, struct tcp_sock* tcp_sk,uint64_t tgid_fd, enum traffic_direction_t direct,ssize_t bytes_count,
			struct conn_info_t* new_conn_info) {
		init_conn_info(tgid_fd>>32, (uint32_t)tgid_fd, new_conn_info);
		struct sock_key key = {0};
		parse_sock_key_sk((struct sock*)tcp_sk, &key);
		
		// if (new_conn_info->conn_id.upid.pid==1499551) {
		// 	bpf_printk("parse sock!");
		// 	print_sock_key(&key);

		// }
		new_conn_info->laddr.in6.sin6_port = key.sport;
		new_conn_info->raddr.in6.sin6_port =  key.dport;
		uint16_t family = -1;
		struct sock_common *sk_common = (struct sock_common *) tcp_sk;
		bool usev6 = use_ipv6(sk_common);
		if (usev6) {
			BPF_CORE_READ_INTO(&family, sk_common, skc_family);
		} else {
			family = AF_INET;
		}
		if (family == AF_INET) {
			new_conn_info->laddr.in6.sin6_addr.in6_u.u6_addr32[0] = (u32)key.sip[0];
			new_conn_info->raddr.in6.sin6_addr.in6_u.u6_addr32[0] = (u32)key.dip[0];
			// new_conn_info->laddr.in4.sin_addr.s_addr = (u32)key.sip[0] ;
			// new_conn_info->raddr.in4.sin_addr.s_addr = (u32)key.dip[0];
		} else if (family == AF_INET6) {
			bpf_probe_read_kernel(&new_conn_info->laddr.in6.sin6_addr, sizeof(struct in6_addr), key.sip);
			bpf_probe_read_kernel(&new_conn_info->raddr.in6.sin6_addr, sizeof(struct in6_addr), key.dip);
		}
		new_conn_info->laddr.sa.sa_family = family;
		new_conn_info->raddr.sa.sa_family = family;

		// new_conn_info->laddr.in4.sin_addr.s_addr =  key.sip;
		// new_conn_info->laddr.in4.sin_port = key.sport;
		// new_conn_info->raddr.in4.sin_addr.s_addr =  key.dip ;
		// new_conn_info->raddr.in4.sin_port =  key.dport;
		bool created = create_conn_info(ctx, new_conn_info, tgid_fd, &key, kRoleUnknown, bpf_ktime_get_ns());
		if (!created) {
			return false;
		}
		
		u32 send_initial_seq = 0;
		u32 rcv_initial_seq = 0;
		u32 write_seq = _C(tcp_sk, write_seq);
		u32 copied_seq = _C(tcp_sk, copied_seq);
		if (direct == kEgress) {
			send_initial_seq = write_seq - bytes_count - 1;
			rcv_initial_seq = copied_seq - 1;
			// bpf_printk("send initial_seq: %u", initial_seq); x-28 [27] x
		} else {
			send_initial_seq = write_seq - 1;
			rcv_initial_seq = copied_seq - bytes_count - 1;
			// bpf_printk("recv initial_seq: %u", initial_seq);
		}
		bpf_map_update_elem(&sock_xmit_map, &key, &send_initial_seq, BPF_ANY);
		parse_sock_key_rcv_sk((struct sock*)tcp_sk, &key);
		bpf_map_update_elem(&sock_xmit_map, &key, &rcv_initial_seq, BPF_ANY);
		return true;
}

static __always_inline void process_syscall_data_vecs(void* ctx, struct data_args *args, uint64_t id, enum traffic_direction_t direct,
	ssize_t bytes_count, bool is_in_nested_ssl) {
		
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
	struct tcp_sock* tcp_sk = NULL;
	if (!conn_info) {
		tcp_sk = get_socket_from_fd(args->fd);
		if (tcp_sk) {
			int zero = 0;
			// struct conn_info_t *new_conn_info = bpf_map_lookup_elem(&conn_info_t_map, &zero);
			struct conn_info_t _new_conn_info = {};
			struct conn_info_t *new_conn_info = &_new_conn_info;
			if (new_conn_info) {
				new_conn_info->protocol = kProtocolUnset;
				bool created = create_conn_info_in_data_syscall(ctx, tcp_sk, tgid_fd, direct, bytes_count, new_conn_info);
				if (created) {
					conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
				}
			}
		}
	} 
	if (!conn_info) {
		return;
	}
	if (is_in_nested_ssl) {
		// bpf_printk("set ssl=true for tgid: %lld, fd: %d", tgid, args->fd);
		conn_info->ssl = true;
	}
	if (!conn_info->ssl) {

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
					
					if (before_infer != protocol_message.protocol) {
						conn_info->protocol = protocol_message.protocol;
						// bpf_printk("[protocol infer]: %d", conn_info->protocol);
						
						if (conn_info->role == kRoleUnknown && protocol_message.type != kUnknown) {
							conn_info->role = ((direct == kEgress) ^ (protocol_message.type == kResponse))
												? kRoleClient
												: kRoleServer;
						}
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
		// conn_id_s.direct = direct;
		enum step_t step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
		if (should_trace_conn(conn_info)) {
			report_syscall_evt_vecs(ctx, seq, &conn_id_s, bytes_count, step, args);
		}
	} else {
		// only report syscall event without data
		uint64_t seq = (direct == kEgress ? conn_info->write_bytes : conn_info->read_bytes) + 1;
		struct conn_id_s_t conn_id_s;
		conn_id_s.tgid_fd = tgid_fd;
		enum step_t step = direct == kEgress ? SYSCALL_OUT : SYSCALL_IN;
		report_syscall_buf_without_data(ctx, seq, &conn_id_s, bytes_count, step, 0, args->source_fn);
	}
	
	
	if (direct == kEgress) {
		conn_info->write_bytes += bytes_count;
	} else {
		conn_info->read_bytes += bytes_count;
	}
}


static __always_inline void process_syscall_data(void* ctx, struct data_args *args, uint64_t id, enum traffic_direction_t direct,
	ssize_t bytes_count, bool is_nested_ssl) {
	if (bytes_count <= 0) {
		// This read()/write() call failed, or processed nothing.
		return;
	}
	uint32_t tgid = id >> 32;
	if (match_trace_tgid(tgid) == TARGET_TGID_UNMATCHED) {
		return;
	}
	uint64_t tgid_fd = gen_tgid_fd(tgid, args->fd);
	struct conn_info_t* conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
	struct tcp_sock* tcp_sk = NULL;
	if (!conn_info) {
		tcp_sk = get_socket_from_fd(args->fd);
		if (tcp_sk) {
			int zero = 0;
			// struct conn_info_t *new_conn_info = bpf_map_lookup_elem(&conn_info_t_map, &zero);
			struct conn_info_t _new_conn_info = {};
			struct conn_info_t *new_conn_info = &_new_conn_info;
			if (new_conn_info) {
				new_conn_info->protocol = kProtocolUnset;
				bool created = create_conn_info_in_data_syscall(ctx, tcp_sk, tgid_fd, direct, bytes_count, new_conn_info);
				if (created) {
					conn_info = bpf_map_lookup_elem(&conn_info_map, &tgid_fd);
				}
			}
		}
	} 

	if (!conn_info) {
		return;
	}

	if (is_nested_ssl) {
		conn_info->ssl = true;
	}

	process_syscall_data_with_conn_info(ctx, args, tgid_fd, direct, bytes_count, conn_info, 0, false, !conn_info->ssl);
	
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

static __always_inline bool update_fd_and_syscall_len_to_uprobe(struct nested_syscall_fd_t* nested_syscall_fd_ptr, int fd, int len) {
	
	// bpf_printk("propagate_fd_to_uprobe, tgid: %lld, fd: %lld, len:%d",pid_tgid >> 32, fd ,len);
	int current_fd = nested_syscall_fd_ptr->fd;
	if (current_fd == kInvalidFD) {
		nested_syscall_fd_ptr->fd = fd;
	} else if (current_fd != fd) {
		nested_syscall_fd_ptr->mismatched_fds = true;
	}
	if (len > 0) {
		nested_syscall_fd_ptr->syscall_len = nested_syscall_fd_ptr->syscall_len + len;
	}
	// uint32_t tgid = pid_tgid >> 32;
	return true;
}

static __always_inline bool propagate_fd_to_uprobe(void* ctx, uint64_t pid_tgid, int fd, uint32_t len) {
	struct nested_syscall_fd_t* nested_syscall_fd_ptr = bpf_map_lookup_elem(&ssl_user_space_call_map, &pid_tgid);
	if (nested_syscall_fd_ptr) {
		// bpf_printk("propagate_fd_to_uprobe, tgid: %lld, fd: %lld, len:%d",pid_tgid >> 32, fd ,len);
		update_fd_and_syscall_len_to_uprobe(nested_syscall_fd_ptr, fd, len);
	} else {
		// return false;
	}
	uint64_t goid = get_goid(ctx);
	if (goid != 0) {
		uint32_t tgid = pid_tgid >> 32;
		struct tgid_goid_t tgid_goid = {};
		tgid_goid.tgid= tgid;
		tgid_goid.goid=goid;
		nested_syscall_fd_ptr = bpf_map_lookup_elem(&go_ssl_user_space_call_map,&tgid_goid);
		if (nested_syscall_fd_ptr) {
			// bpf_printk("propagate_fd_to_uprobe, tgid: %lld, fd: %lld, len:%d",pid_tgid >> 32, fd ,len);
			update_fd_and_syscall_len_to_uprobe(nested_syscall_fd_ptr, fd, len);
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data(ctx, args, id, kIngress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data(ctx, args, id, kIngress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, read_args->fd, bytes_count);
		process_syscall_data_vecs(ctx, read_args, id, kIngress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data_vecs(ctx, args, id, kIngress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data(ctx, args, id, kEgress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data(ctx, args, id, kEgress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data_vecs(ctx, args, id, kEgress, bytes_count, is_ssl);
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
		bool is_ssl = propagate_fd_to_uprobe(ctx, id, args->fd, bytes_count);
		process_syscall_data_vecs(ctx, args, id, kEgress, bytes_count, is_ssl);
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

#ifdef ARCH_amd64
		BPF_CORE_READ_INTO(&sk, ctx, ax);
#else
		sk = PT_REGS_RC_CORE(ctx);
#endif
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


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} proc_exec_events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} proc_exit_events SEC(".maps");

struct process_exec_event {
	int pid;
};

struct process_exit_event {
	int pid;
};

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
	struct process_exec_event event = {0};
	uint64_t id = bpf_get_current_pid_tgid();
	uint32_t tgid = id >> 32;
	uint32_t tid = id;

	bool is_thread_group_leader = tgid == tid;
	if (is_thread_group_leader) {
		event.pid = tgid;
		bpf_perf_event_output(ctx, &proc_exec_events, BPF_F_CURRENT_CPU, &event, sizeof(struct process_exec_event));
	}
	return BPF_OK;
}


SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_exec *ctx) {
	struct process_exit_event event = {0};
	uint64_t id = bpf_get_current_pid_tgid();
	uint32_t tgid = id >> 32;
	uint32_t tid = id;

	bool is_thread_group_leader = tgid == tid;
	if (is_thread_group_leader) {
		event.pid = tgid;
		bpf_perf_event_output(ctx, &proc_exit_events, BPF_F_CURRENT_CPU, &event, sizeof(struct process_exit_event));
	}
	return BPF_OK;
}