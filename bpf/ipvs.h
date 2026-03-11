#ifndef __IPVS_H__
#define __IPVS_H__

// IPVS 事件类型定义
#define EVENT_CONN_NEW      0   // 新建连接
#define EVENT_CONN_IN       1   // 入站连接查找
#define EVENT_CONN_OUT      2   // 出站连接查找
#define EVENT_SCHEDULE      3   // 调度选择后端
#define EVENT_NAT_XMIT      4   // NAT 模式转发
#define EVENT_DR_XMIT       5   // DR 模式转发
#define EVENT_TUNNEL_XMIT   6   // 隧道模式转发
#define EVENT_CONN_PUT      7   // 释放连接引用

// IPVS 事件结构体
struct ipvs_event_t {
    __u64 timestamp_ns;     // 事件时间戳
    __u64 latency_ns;       // 函数执行延迟
    __u64 conn_ptr;         // ip_vs_conn 指针
    __u64 skb_ptr;          // sk_buff 指针
    __u32 pid;              // 进程 ID
    __u8 event_type;        // 事件类型
    __u8 protocol;          // 协议 (TCP/UDP)
    __u16 conn_flags;       // 连接标志
    __be32 client_ip;       // 客户端 IP
    __be16 client_port;     // 客户端端口
    __be32 vip;             // 虚拟 IP
    __be16 vport;           // 虚拟端口
    __be32 real_ip;         // 真实服务器 IP
    __be16 real_port;       // 真实服务器端口
    char comm[16];          // 进程名
} __attribute__((packed));

// 函数入口信息结构体
struct entry_info_t {
    __u64 start_ns;         // 入口时间戳
    __u64 conn_ptr;         // 连接指针
    __u64 skb_ptr;          // skb 指针
};

// 注意：nf_inet_addr 已在 vmlinux.h 中定义，不需要重复定义

// ip_vs_conn 结构体定义（简化版本，仅包含需要的字段）
// 基于 Linux 内核 include/net/ip_vs.h
// 注意：这是一个简化版本，字段偏移可能因内核版本而异
struct ip_vs_conn {
    // 哈希链表节点
    struct hlist_node c_list;
    
    // 地址和端口信息
    union nf_inet_addr caddr;       // 客户端地址
    union nf_inet_addr vaddr;       // 虚拟地址
    union nf_inet_addr daddr;       // 目标（真实服务器）地址
    volatile __u32 flags;           // 连接标志
    __u16 protocol;                 // 协议
    __u16 dport;                    // 目标端口
    __u16 vport;                    // 虚拟端口
    __u16 cport;                    // 客户端端口
    // 后续字段省略...
};

// ip_vs_service 结构体（前向声明）
struct ip_vs_service;

// ip_vs_protocol 结构体（前向声明）
struct ip_vs_protocol;

// ip_vs_iphdr 结构体（前向声明）
struct ip_vs_iphdr;

#endif /* __IPVS_H__ */
