//go:build ignore

// IPVS 追踪 BPF 程序
// 用于追踪 IPVS 负载均衡的连接和转发事件

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ipvs.h"

char LICENSE[] SEC("license") = "GPL";

// Perf 事件输出 map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ipvs_events SEC(".maps");

// 函数入口信息 map（用于计算延迟）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // pid_tgid
    __type(value, struct entry_info_t);
} ipvs_entry_map SEC(".maps");

// skb 到 conn 的映射（用于与 L7 关联）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // skb 指针
    __type(value, __u64); // conn 指针
} ipvs_skb_conn_map SEC(".maps");

// ip_vs_conn 结构体字段偏移量（基于 Linux 5.x 内核）
// 这些偏移量可能因内核版本而异，但对于大多数现代内核应该是正确的
// struct ip_vs_conn 布局:
//   hlist_node c_list (16 bytes on 64-bit)
//   nf_inet_addr caddr (16 bytes)
//   nf_inet_addr vaddr (16 bytes)
//   nf_inet_addr daddr (16 bytes)
//   volatile __u32 flags (4 bytes)
//   __u16 protocol (2 bytes)
//   __u16 dport (2 bytes)
//   __u16 vport (2 bytes)
//   __u16 cport (2 bytes)
#define IPVS_CONN_CADDR_OFFSET  16   // hlist_node 之后
#define IPVS_CONN_VADDR_OFFSET  32   // caddr 之后
#define IPVS_CONN_DADDR_OFFSET  48   // vaddr 之后
#define IPVS_CONN_FLAGS_OFFSET  64   // daddr 之后
#define IPVS_CONN_PROTO_OFFSET  68   // flags 之后
#define IPVS_CONN_DPORT_OFFSET  70   // protocol 之后
#define IPVS_CONN_VPORT_OFFSET  72   // dport 之后
#define IPVS_CONN_CPORT_OFFSET  74   // vport 之后

// 辅助函数：从 ip_vs_conn 读取连接信息
static __always_inline void read_conn_info(void *conn_ptr, struct ipvs_event_t *event) {
    if (conn_ptr == NULL) {
        return;
    }
    
    // 读取协议
    bpf_probe_read_kernel(&event->protocol, sizeof(event->protocol), 
                          conn_ptr + IPVS_CONN_PROTO_OFFSET);
    
    // 读取连接标志
    __u32 flags = 0;
    bpf_probe_read_kernel(&flags, sizeof(flags), 
                          conn_ptr + IPVS_CONN_FLAGS_OFFSET);
    event->conn_flags = (__u16)flags;
    
    // 读取客户端地址（nf_inet_addr 的第一个 __be32 是 IPv4 地址）
    bpf_probe_read_kernel(&event->client_ip, sizeof(event->client_ip), 
                          conn_ptr + IPVS_CONN_CADDR_OFFSET);
    bpf_probe_read_kernel(&event->client_port, sizeof(event->client_port), 
                          conn_ptr + IPVS_CONN_CPORT_OFFSET);
    
    // 读取虚拟地址
    bpf_probe_read_kernel(&event->vip, sizeof(event->vip), 
                          conn_ptr + IPVS_CONN_VADDR_OFFSET);
    bpf_probe_read_kernel(&event->vport, sizeof(event->vport), 
                          conn_ptr + IPVS_CONN_VPORT_OFFSET);
    
    // 读取真实服务器地址
    bpf_probe_read_kernel(&event->real_ip, sizeof(event->real_ip), 
                          conn_ptr + IPVS_CONN_DADDR_OFFSET);
    bpf_probe_read_kernel(&event->real_port, sizeof(event->real_port), 
                          conn_ptr + IPVS_CONN_DPORT_OFFSET);
}

// 辅助函数：发送事件
static __always_inline void send_event(void *ctx, __u8 event_type, 
                                        __u64 latency_ns, __u64 conn_ptr, 
                                        __u64 skb_ptr) {
    struct ipvs_event_t event = {};
    
    event.timestamp_ns = bpf_ktime_get_ns();
    event.latency_ns = latency_ns;
    event.conn_ptr = conn_ptr;
    event.skb_ptr = skb_ptr;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = event_type;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // 如果有 conn 指针，读取连接信息
    if (conn_ptr != 0) {
        read_conn_info((void *)conn_ptr, &event);
    }
    
    bpf_perf_event_output(ctx, &ipvs_events, BPF_F_CURRENT_CPU, 
                          &event, sizeof(event));
}

// 辅助函数：记录函数入口
static __always_inline void record_entry(__u64 conn_ptr, __u64 skb_ptr) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct entry_info_t info = {
        .start_ns = bpf_ktime_get_ns(),
        .conn_ptr = conn_ptr,
        .skb_ptr = skb_ptr,
    };
    bpf_map_update_elem(&ipvs_entry_map, &pid_tgid, &info, BPF_ANY);
}

// 辅助函数：获取函数入口信息并计算延迟
static __always_inline struct entry_info_t *get_entry_and_delete(void) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct entry_info_t *info = bpf_map_lookup_elem(&ipvs_entry_map, &pid_tgid);
    if (info) {
        bpf_map_delete_elem(&ipvs_entry_map, &pid_tgid);
    }
    return info;
}

// ============================================================================
// ip_vs_conn_new: 新建 IPVS 连接
// ============================================================================
SEC("kprobe/ip_vs_conn_new")
int BPF_KPROBE(kprobe_ip_vs_conn_new) {
    record_entry(0, 0);
    return 0;
}

SEC("kretprobe/ip_vs_conn_new")
int BPF_KRETPROBE(kretprobe_ip_vs_conn_new, struct ip_vs_conn *ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    __u64 conn_ptr = (__u64)ret;
    
    send_event(ctx, EVENT_CONN_NEW, latency, conn_ptr, 0);
    return 0;
}

// ============================================================================
// ip_vs_conn_in_get: 入站连接查找
// ============================================================================
SEC("kprobe/ip_vs_conn_in_get")
int BPF_KPROBE(kprobe_ip_vs_conn_in_get) {
    record_entry(0, 0);
    return 0;
}

SEC("kretprobe/ip_vs_conn_in_get")
int BPF_KRETPROBE(kretprobe_ip_vs_conn_in_get, struct ip_vs_conn *ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    __u64 conn_ptr = (__u64)ret;
    
    send_event(ctx, EVENT_CONN_IN, latency, conn_ptr, 0);
    return 0;
}

// ============================================================================
// ip_vs_conn_out_get: 出站连接查找
// ============================================================================
SEC("kprobe/ip_vs_conn_out_get")
int BPF_KPROBE(kprobe_ip_vs_conn_out_get) {
    record_entry(0, 0);
    return 0;
}

SEC("kretprobe/ip_vs_conn_out_get")
int BPF_KRETPROBE(kretprobe_ip_vs_conn_out_get, struct ip_vs_conn *ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    __u64 conn_ptr = (__u64)ret;
    
    send_event(ctx, EVENT_CONN_OUT, latency, conn_ptr, 0);
    return 0;
}

// ============================================================================
// ip_vs_schedule: 调度选择后端服务器
// ============================================================================
SEC("kprobe/ip_vs_schedule")
int BPF_KPROBE(kprobe_ip_vs_schedule, struct ip_vs_service *svc,
               struct sk_buff *skb) {
    __u64 skb_ptr = (__u64)skb;
    record_entry(0, skb_ptr);
    return 0;
}

SEC("kretprobe/ip_vs_schedule")
int BPF_KRETPROBE(kretprobe_ip_vs_schedule, struct ip_vs_conn *ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    __u64 conn_ptr = (__u64)ret;
    __u64 skb_ptr = info->skb_ptr;
    
    // 记录 skb 到 conn 的映射
    if (skb_ptr != 0 && conn_ptr != 0) {
        bpf_map_update_elem(&ipvs_skb_conn_map, &skb_ptr, &conn_ptr, BPF_ANY);
    }
    
    send_event(ctx, EVENT_SCHEDULE, latency, conn_ptr, skb_ptr);
    return 0;
}

// ============================================================================
// ip_vs_nat_xmit: NAT 模式转发
// ============================================================================
SEC("kprobe/ip_vs_nat_xmit")
int BPF_KPROBE(kprobe_ip_vs_nat_xmit, struct sk_buff *skb,
               struct ip_vs_conn *cp,
               struct ip_vs_protocol *pp,
               struct ip_vs_iphdr *ipvsh) {
    __u64 conn_ptr = (__u64)cp;
    __u64 skb_ptr = (__u64)skb;
    record_entry(conn_ptr, skb_ptr);
    return 0;
}

SEC("kretprobe/ip_vs_nat_xmit")
int BPF_KRETPROBE(kretprobe_ip_vs_nat_xmit, int ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    
    send_event(ctx, EVENT_NAT_XMIT, latency, info->conn_ptr, info->skb_ptr);
    return 0;
}

// ============================================================================
// ip_vs_dr_xmit: DR 模式转发
// ============================================================================
SEC("kprobe/ip_vs_dr_xmit")
int BPF_KPROBE(kprobe_ip_vs_dr_xmit, struct sk_buff *skb,
               struct ip_vs_conn *cp,
               struct ip_vs_protocol *pp,
               struct ip_vs_iphdr *ipvsh) {
    __u64 conn_ptr = (__u64)cp;
    __u64 skb_ptr = (__u64)skb;
    record_entry(conn_ptr, skb_ptr);
    return 0;
}

SEC("kretprobe/ip_vs_dr_xmit")
int BPF_KRETPROBE(kretprobe_ip_vs_dr_xmit, int ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    
    send_event(ctx, EVENT_DR_XMIT, latency, info->conn_ptr, info->skb_ptr);
    return 0;
}

// ============================================================================
// ip_vs_tunnel_xmit: 隧道模式转发
// ============================================================================
SEC("kprobe/ip_vs_tunnel_xmit")
int BPF_KPROBE(kprobe_ip_vs_tunnel_xmit, struct sk_buff *skb,
               struct ip_vs_conn *cp,
               struct ip_vs_protocol *pp,
               struct ip_vs_iphdr *ipvsh) {
    __u64 conn_ptr = (__u64)cp;
    __u64 skb_ptr = (__u64)skb;
    record_entry(conn_ptr, skb_ptr);
    return 0;
}

SEC("kretprobe/ip_vs_tunnel_xmit")
int BPF_KRETPROBE(kretprobe_ip_vs_tunnel_xmit, int ret) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    
    send_event(ctx, EVENT_TUNNEL_XMIT, latency, info->conn_ptr, info->skb_ptr);
    return 0;
}

// ============================================================================
// ip_vs_conn_put: 释放连接引用
// ============================================================================
SEC("kprobe/ip_vs_conn_put")
int BPF_KPROBE(kprobe_ip_vs_conn_put, struct ip_vs_conn *cp) {
    __u64 conn_ptr = (__u64)cp;
    record_entry(conn_ptr, 0);
    return 0;
}

SEC("kretprobe/ip_vs_conn_put")
int BPF_KRETPROBE(kretprobe_ip_vs_conn_put) {
    struct entry_info_t *info = get_entry_and_delete();
    if (!info) return 0;
    
    __u64 latency = bpf_ktime_get_ns() - info->start_ns;
    
    send_event(ctx, EVENT_CONN_PUT, latency, info->conn_ptr, 0);
    return 0;
}
