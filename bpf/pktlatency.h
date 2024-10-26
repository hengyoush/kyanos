#ifndef __KPROBE_H__
#define __KPROBE_H__

#define PX_AF_UNKNOWN 0xff
#define AF_INET 2
#define AF_INET6 10
#define MAX_MSG_SIZE 30720
#define EINPROGRESS 115

// #include <bpf/bpf_tracing.h>
// #include <bpf/bpf_endian.h>
// #include <linux/in.h>
// #include <linux/in6.h> 
// #include <linux/socket.h>

enum step_t {
  start = 0,
  SSL_OUT,
  SYSCALL_OUT,
  TCP_OUT,
  IP_OUT,
  QDISC_OUT,
  DEV_OUT,
  NIC_OUT,
  NIC_IN,
  DEV_IN,
  IP_IN,
  TCP_IN,
  USER_COPY,
  SYSCALL_IN,
  SSL_IN,
  end
};

enum traffic_protocol_t {
  kProtocolUnset = 0,
  kProtocolUnknown,
  kProtocolHTTP,
  kProtocolHTTP2,
  kProtocolMySQL,
  kProtocolCQL,
  kProtocolPGSQL,
  kProtocolDNS,
  kProtocolRedis,
  kProtocolNATS,
  kProtocolMongo,
  kProtocolKafka,
  kProtocolMux,
  kProtocolAMQP,
  kNumProtocols
};

enum endpoint_role_t {
  kRoleClient = 1 << 0,
  kRoleServer = 1 << 1,
  kRoleUnknown = 1 << 2,
};

enum source_function_t {
  kSourceFunctionUnknown,

  // For syscalls.
  kSyscallAccept,
  kSyscallConnect,
  kSyscallClose,
  kSyscallWrite,
  kSyscallRead,
  kSyscallSend,
  kSyscallRecv,
  kSyscallSendTo,
  kSyscallRecvFrom,
  kSyscallSendMsg,
  kSyscallRecvMsg,
  kSyscallSendMMsg,
  kSyscallRecvMMsg,
  kSyscallWriteV,
  kSyscallReadV,
  kSyscallSendfile,

  // For Go TLS libraries.
  kGoTLSConnWrite,
  kGoTLSConnRead,

  // For SSL libraries.
  kSSLWrite,
  kSSLRead,
};

enum control_value_index_t {
  // This specify one pid to monitor. This is used during test to eliminate noise.
  // TODO: We need a more robust mechanism for production use, which should be able to:
  // * Specify multiple pids up to a certain limit, let's say 1024.
  // * Support efficient lookup inside bpf to minimize overhead.
  kTargetTGIDIndex = 0,
  kStirlingTGIDIndex,
  kEnabledXdpIndex,
  kEnableFilterByPid,
  kEnableFilterByLocalPort,
  kEnableFilterByRemotePort,
  kEnableFilterByRemoteHost,
  kSideFilter, // 0-all 1-server 2-client
  kNumControlValues,
};

enum message_type_t { kUnknown, kRequest, kResponse };

struct protocol_message_t {
  enum traffic_protocol_t protocol;
  enum message_type_t type;
};

enum traffic_direction_t {
  kEgress,
  kIngress,
};

enum conn_type_t {
  kConnect,
  kClose,
  kProtocolInfer,
};

struct sock_key {
	uint64_t sip[2];
	uint64_t dip[2];
	uint16_t sport;
	uint16_t dport;
};

#define FUNC_NAME_LIMIT 16 
#define CMD_LEN 16 

// struct event {
// 	pid_t pid;
// 	uint32_t init_seq;
// 	uint32_t tcp_seq;
// 	struct sock_key *key;
// 	uint32_t cur_seq;
// 	uint32_t data_len;
// 	bool is_sample;
// 	__u64 ts;
// 	uint32_t inode;
// };


struct upid_t {
  union {
    uint32_t pid;
    uint32_t tgid;
  };
  uint64_t start_time_ticks;
};

struct conn_id_t {
  //  pid/tgid.
  struct upid_t upid;
  // The file descriptor to the opened network connection.
  int32_t fd;
  // Unique id of the conn_id (timestamp).
  uint64_t tsid;
};


struct conn_id_s_t {
	uint64_t tgid_fd;
  bool no_trace;
};

struct kern_evt {
	char func_name[FUNC_NAME_LIMIT];
	uint64_t ts;
	uint64_t seq;
	uint32_t len;
  uint8_t flags;
	uint32_t ifindex;
  struct conn_id_s_t conn_id_s;
  enum step_t step;
};
#define MAX_MSG_SIZE 30720
struct kern_evt_data {
  struct kern_evt ke;
  uint32_t buf_size;
  char msg[MAX_MSG_SIZE];
};
struct kern_evt_ssl_data {
  struct kern_evt ke;
	uint64_t syscall_seq;
	uint32_t syscall_len;
  uint32_t buf_size;
  char msg[MAX_MSG_SIZE];
};


// struct data_evt {
//   uint64_t tgid_fd;
// };


static inline void my_strcpy(char *dest, const char *src, int n) {
    int i = 0;
	int LIMIT = n;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
		if (i >= LIMIT) {
			i--;
			break;
		}
    }
    dest[i] = '\0';
}


struct data_args {
  // Represents the function from which this argument group originates.
  enum source_function_t source_fn;

  // Did the data event call sock_sendmsg/sock_recvmsg.
  // Used to filter out read/write and readv/writev calls that are not to sockets.
  int sock_event;

  int32_t fd;

  // For send()/recv()/write()/read().
  const char* buf;

  // For sendmsg()/recvmsg()/writev()/readv().
  const struct iovec* iov;
  size_t iovlen;

  // For sendmmsg()
  unsigned int* msg_len;
  size_t* ssl_ex_len;
  uint64_t ts;
};
struct close_args {
  uint32_t fd;
};

struct connect_args {
  const struct sockaddr* addr;
  int32_t fd;
  uint64_t start_ts;
};

struct accept_args {
  struct sockaddr* addr;
  struct socket* sock_alloc_socket;
};



union sockaddr_t {
  struct sockaddr_in6 in6;
  struct sockaddr_in in4;
  struct sockaddr sa;
};
struct conn_info_t {
  // Connection identifier (PID, FD, etc.).
  struct conn_id_t conn_id;
  uint64_t read_bytes;
  uint64_t write_bytes;
  uint64_t ssl_read_bytes;
  uint64_t ssl_write_bytes;

  // IP address of the local endpoint.
  union sockaddr_t laddr;
  union sockaddr_t raddr;

  // The protocol of traffic on the connection (HTTP, MySQL, etc.).
  enum traffic_protocol_t protocol;
  // Classify traffic as requests, responses or mixed.
  enum endpoint_role_t role;
  // Keep the header of the last packet suspected to be MySQL/Kafka. MySQL/Kafka server does 2
  // separate read syscalls, first to read the header, and second the body of the packet. Thus, we
  // keep a state. (MySQL): Length(3 bytes) + seq_number(1 byte). (Kafka): Length(4 bytes)
  size_t prev_count;
  char prev_buf[4];
  bool prepend_length_header;
  
  bool no_trace;
  bool ssl;
};


struct conn_evt_t {
  struct conn_info_t conn_info;
  enum conn_type_t  conn_type;
	uint64_t ts;
};


struct parse_kern_evt_body {
	void* ctx;
	u32 inital_seq;
	struct sock_key *key;
	u32 cur_seq;
	u32 len;
	const char *func_name;
	enum step_t step;
  struct tcphdr* tcp;
  u32 ifindex;
};

// const char SYSCALL_FUNC_NAME[] = "syscall";
// const char XDP_FUNC_NAME[] = "xdp";
// const char SKB_COPY_FUNC_NAME[] = "skb_copy_datagram_iter";
// const char NET_RECEIVE_SKB_FUNC_NAME[] = "netif_receive_skb";
// const char TCP_RCV_FUNC_NAME[] = "tcp_v4_do_rcv";
// const char IP_RCV_FUNC_NAME[] = "ip_rcv_core";
// const char DEV_HARD_XMIT_FUNC_NAME[] = "dev_hard_start_xmit";
// const char DEV_QUEUE_XMIT_FUNC_NAME[] = "dev_queue_xmit";
// const char IP_QUEUE_XMIT_FUNC_NAME[] = "ip_queue_xmit";

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



#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
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

struct nf_conntrack_tuple___custom {
    struct nf_conntrack_man src;
    struct {
        union nf_inet_addr u3;
        union {
            __be16 all;
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                u_int8_t type;
                u_int8_t code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        u_int8_t protonum;
        u_int8_t dir;
    } dst;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_hash___custom {
    struct hlist_nulls_node hnnode;
    struct nf_conntrack_tuple___custom tuple;
} __attribute__((preserve_access_index));
// https://elixir.bootlin.com/linux/v5.2.21/source/include/net/netfilter/nf_conntrack.h
struct nf_conn___older_52 {
    struct nf_conntrack ct_general;
    spinlock_t lock;
    u16 ___cpu;
    struct nf_conntrack_zone zone;
    struct nf_conntrack_tuple_hash___custom tuplehash[IP_CT_DIR_MAX];
} __attribute__((preserve_access_index));

#endif		
