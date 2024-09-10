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
	uint32_t sip;
	uint32_t dip;
	uint32_t sport;
	uint32_t dport;
	uint32_t family;
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
	// 0-入向 1-出向
	enum traffic_direction_t direct;
};

struct kern_evt {
	char func_name[FUNC_NAME_LIMIT];
	uint64_t ts;
	uint64_t seq;
	uint32_t len;
  uint8_t flags;
  struct conn_id_s_t conn_id_s;
	int is_sample;
  enum step_t step;
};
#define MAX_MSG_SIZE 30720
struct kern_evt_data {
  struct kern_evt ke;
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
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};
struct conn_info_t {
  // Connection identifier (PID, FD, etc.).
  struct conn_id_t conn_id;
  uint64_t read_bytes;
  uint64_t write_bytes;

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
	char *func_name;
	enum step_t step;
  struct tcphdr* tcp;
};
#endif		
