#ifndef __P_INFER_H__
#define __P_INFER_H__

#include "pktlatency.h"
// MySQL packet:
//      0         8        16        24        32
//      +---------+---------+---------+---------+
//      |        payload_length       | seq_id  |
//      +---------+---------+---------+---------+
//      |                                       |
//      .            ...  body ...              .
//      .                                       . 
//      .                                       .
//      +----------------------------------------
static __always_inline int is_mysql_protocol(const char *old_buf, size_t count, struct conn_info_t *conn_info) {
  static const uint8_t kComQuery = 0x03;
  static const uint8_t kComConnect = 0x0b;
  static const uint8_t kComStmtPrepare = 0x16;
  static const uint8_t kComStmtExecute = 0x17;
  static const uint8_t kComStmtClose = 0x19;

  // Second statement checks whether suspected header matches the length of current packet.
  bool use_prev_buf = (conn_info->prev_count == 4) && (*((uint32_t*)conn_info->prev_buf) == count);
  // if (conn_info->prev_count == 4) {
  //   bpf_printk("prevbuf: %d", (*((uint32_t*)conn_info->prev_buf)));
  // }
  if (use_prev_buf) {
    
    // Check the header_state to find out if the header has been read. MySQL server tends to
    // read in the 4 byte header and the rest of the packet in a separate read.
    count += 4;
  }

  // MySQL packets start with a 3-byte packet length and a 1-byte packet number.
  // The 5th byte on a request contains a command that tells the type.
  if (count < 5) {
    return kUnknown;
  }

  // Convert 3-byte length to uint32_t. But since the 4th byte is supposed to be \x00, directly
  // casting 4-bytes is correct.
  // NOLINTNEXTLINE: readability/casting
  char buf[5] = {};
  bpf_probe_read_user(buf, 5, old_buf);
  uint32_t len = use_prev_buf ? *((uint32_t*)conn_info->prev_buf) : *((uint32_t*)buf);
  len = len & 0x00ffffff;

  uint8_t seq = use_prev_buf ? conn_info->prev_buf[3] : buf[3];
  uint8_t com = use_prev_buf ? buf[0] : buf[4];

  // The packet number of a request should always be 0.
  if (seq != 0) {
    return kUnknown;
  }

  // No such thing as a zero-length request in MySQL protocol.
  if (len == 0) {
    return kUnknown;
  }

  // Assuming that the length of a request is less than 10k characters to avoid false
  // positive flagging as MySQL, which statistically happens frequently for a single-byte
  // check.
  if (len > 10000) {
    return kUnknown;
  }

  // TODO(oazizi): Consider adding more commands (0x00 to 0x1f).
  // Be careful, though: trade-off is higher rates of false positives.
  if (com == kComConnect || com == kComQuery || com == kComStmtPrepare || com == kComStmtExecute ||
      com == kComStmtClose) {
    return kRequest;
  }
  return kUnknown;
}

static __always_inline int is_redis_protocol(const char *old_buf, size_t count) {
  if (count < 3) {
    return false;
  }
  
  char buf[1] = {};
  bpf_probe_read_user(buf, 1, old_buf);
  const char first_byte = buf[0];
  if (  // Simple strings start with +
      first_byte != '+' &&
      // Errors start with -
      first_byte != '-' &&
      // Integers start with :
      first_byte != ':' &&
      // Bulk strings start with $
      first_byte != '$' &&
      // Arrays start with *
      first_byte != '*') {
    return false;
  }

  char last_buf[2] = {};
  bpf_probe_read_user(last_buf, 2, old_buf + count - 2);
  if (last_buf[0] != '\r') {
    return false;
  }
  if (last_buf[1] != '\n') {
    return false;
  }
  return true;
}

static __always_inline enum message_type_t is_http_protocol(const char *old_buf, size_t count) {
  if (count < 5) {
    return 0;
  }
  char buf[4] = {};
  bpf_probe_read_user(buf, 4, old_buf);
  if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
    return kResponse;
  }
  if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
    return kRequest;
  }
  if (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') {
    return kRequest;
  }
  if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
    return kRequest;
  }
  return kUnknown;
}

static __always_inline bool is_nats_info(const char *old_buf, size_t count) {
  if (count < 6)
    return false;

  char buf[20];
  int len = 20;
  if (count < 20)
    len = count;
  bpf_probe_read_user(buf, len, old_buf);
  // info
  if (buf[0] != 'I' && buf[0] != 'i')
    return false;
  if (buf[1] != 'N' && buf[1] != 'n')
    return false;
  if (buf[2] != 'F' && buf[2] != 'f')
    return false;
  if (buf[3] != 'O' && buf[3] != 'o')
    return false;
  if (buf[4] != ' ' && buf[4] != '\t')
    return false;

  // NATS allows arbitrary whitespace after INFO
  // we only check the first 20 bytes due to eBPF limitations
  for (int p = 5; p < len; p++)
    if (buf[p] == '{')
      return true;
    else if (buf[p] != ' ' && buf[p] != '\t')
      return false;
  return false;
}

static __always_inline bool is_nats_connect(const char *old_buf, size_t count) {
  if (count < 8)
    return false;

  char buf[20];
  int len = 20;
  if (count < 20)
    len = count;
  bpf_probe_read_user(buf, len, old_buf);

  // connect
  if (buf[0] != 'C' && buf[0] != 'c')
    return false;
  if (buf[1] != 'O' && buf[1] != 'o')
    return false;
  if (buf[2] != 'N' && buf[2] != 'n')
    return false;
  if (buf[3] != 'N' && buf[3] != 'n')
    return false;
  if (buf[4] != 'E' && buf[4] != 'e')
    return false;
  if (buf[5] != 'C' && buf[5] != 'c')
    return false;
  if (buf[6] != 'T' && buf[6] != 't')
    return false;
  if (buf[7] != ' ' && buf[7] != '\t')
    return false;

  // NATS allows arbitrary whitespace after CONNECT
  // we only check the first 20 bytes due to eBPF limitations
  for (int p = 8; p < len; p++)
    if (buf[p] == '{')
      return true;
    else if (buf[p] != ' ' && buf[p] != '\t')
      return false;
  return false;
}

// https://docs.nats.io/reference/reference-protocols/nats-protocol
static __always_inline enum message_type_t is_nats_protocol(const char *old_buf,
                                                            size_t count) {
  if (count < 5) {
    return kUnknown;
  }

  if (is_nats_info(old_buf, count))
    return kResponse;

  if (is_nats_connect(old_buf, count))
    return kRequest;

  char buf[6] = {};
  bpf_probe_read_user(buf, 5, old_buf);
  // pub
  if ((buf[0] == 'P' || buf[0] == 'p') && (buf[1] == 'U' || buf[1] == 'u') &&
      (buf[2] == 'B' || buf[2] == 'b') && (buf[3] == ' ' || buf[3] == '\t')) {
    return kRequest;
  }
  // hpub
  if ((buf[0] == 'H' || buf[0] == 'h') && (buf[1] == 'P' || buf[1] == 'p') &&
      (buf[2] == 'U' || buf[2] == 'u') && (buf[3] == 'B' || buf[3] == 'b') &&
      (buf[4] == ' ' || buf[4] == '\t')) {
    return kRequest;
  }
  // sub
  if ((buf[0] == 'S' || buf[0] == 's') && (buf[1] == 'U' || buf[1] == 'u') &&
      (buf[2] == 'B' || buf[2] == 'b') && (buf[3] == ' ' || buf[3] == '\t')) {
    return kRequest;
  }
  // msg
  if ((buf[0] == 'M' || buf[0] == 'm') && (buf[1] == 'S' || buf[1] == 's') &&
      (buf[2] == 'G' || buf[2] == 'g') && (buf[3] == ' ' || buf[3] == '\t')) {
    return kResponse;
  }
  // hmsg
  if ((buf[0] == 'H' || buf[0] == 'h') && (buf[1] == 'M' || buf[1] == 'm') &&
      (buf[2] == 'S' || buf[2] == 's') && (buf[3] == 'G' || buf[3] == 'g') &&
      (buf[4] == ' ' || buf[4] == '\t')) {
    return kResponse;
  }
  // ping
  if ((buf[0] == 'P' || buf[0] == 'p') && (buf[1] == 'I' || buf[1] == 'i') &&
      (buf[2] == 'N' || buf[2] == 'n') && (buf[3] == 'G' || buf[3] == 'g')) {
    return kRequest;
  }
  // pong
  if ((buf[0] == 'P' || buf[0] == 'p') && (buf[1] == 'O' || buf[1] == 'o') &&
      (buf[2] == 'N' || buf[2] == 'n') && (buf[3] == 'G' || buf[3] == 'g')) {
    return kResponse;
  }
  // +ok
  if ((buf[0] == '+') && (buf[1] == 'O' || buf[1] == 'o') &&
      (buf[2] == 'K' || buf[2] == 'k')) {
    return kResponse;
  }
  // -err
  if ((buf[0] == '-') && (buf[1] == 'E' || buf[1] == 'e') &&
      (buf[2] == 'R' || buf[2] == 'r') && (buf[3] == 'R' || buf[3] == 'r') &&
      (buf[4] == ' ' || buf[4] == '\t')) {
    return kResponse;
  }
  if (count < 6)
    return kUnknown;

  bpf_probe_read_user(buf, 6, old_buf);
  // unsub
  if ((buf[0] == 'U' || buf[0] == 'u') && (buf[1] == 'N' || buf[1] == 'n') &&
      (buf[2] == 'S' || buf[2] == 's') && (buf[3] == 'U' || buf[3] == 'u') &&
      (buf[4] == 'B' || buf[4] == 'b') && (buf[5] == ' ' || buf[5] == '\t')) {
    return kRequest;
  }
  return kUnknown;
}

static __always_inline enum message_type_t is_rocketmq_protocol(
    const char *old_buf, size_t count) {
  if (count < 16) {
    return kUnknown;
  }

  int32_t frame_size;
  bpf_probe_read_user(&frame_size, sizeof(int32_t), old_buf);
  frame_size = bpf_ntohl(frame_size);

  if (frame_size <= 0 || frame_size > (count - 4)) {
    return kUnknown;
  }

  int32_t header_length = 0;
  bpf_probe_read_user(&header_length, sizeof(int32_t), old_buf + 4);
  header_length = bpf_ntohl(header_length);

  char serialized_type = (header_length >> 24) & 0xFF;
  if (serialized_type != 0x0 && serialized_type != 0x1) {
    return kUnknown;
  }

  int32_t header_data_len = header_length & 0xFFFFFF;
  // bpf_printk("header_data_len : %d", header_data_len);
  if (header_data_len <= 0 || header_data_len != (frame_size - 4)) {
    return kUnknown;
  }

  if (serialized_type == 0x0) {  // json format
    char buf[8] = {};
    bpf_probe_read_user(buf, 8, old_buf + 8);
    if (buf[0] != '{' || buf[1] != '"' || buf[2] != 'c' || buf[3] != 'o' ||
        buf[4] != 'd' || buf[5] != 'e' || buf[6] != '"' || buf[7] != ':') {
      // {"code":
      return kUnknown;
    }
  } else if (serialized_type == 0x1) {
    uint16_t request_code = 0;
    uint8_t l_flag = 0;
    uint16_t v_flag = 0;

    bpf_probe_read_user(&request_code, sizeof(uint16_t), old_buf + 8);
    bpf_probe_read_user(&l_flag, sizeof(uint8_t), old_buf + 10);
    bpf_probe_read_user(&v_flag, sizeof(uint16_t), old_buf + 11);

    // rocketmq/remoting/protocol/RequestCode.java
    request_code = bpf_ntohl(request_code);
    if (request_code < 10) {
      return kUnknown;
    }

    if (l_flag > 13) {
      return kUnknown;
    }
  }
  return kRequest;
}

static __always_inline struct protocol_message_t infer_protocol(const char *buf, size_t count, struct conn_info_t *conn_info) {
  struct protocol_message_t protocol_message;
  protocol_message.protocol = kProtocolUnknown;
  protocol_message.type = kUnknown;
  if ((protocol_message.type = is_http_protocol(buf, count)) != kUnknown) {
    protocol_message.protocol = kProtocolHTTP;
  } else if ((protocol_message.type = is_mysql_protocol(buf, count, conn_info)) != kUnknown)  {
    protocol_message.protocol = kProtocolMySQL;
  } else if (is_redis_protocol(buf, count)) {
    protocol_message.protocol = kProtocolRedis;
  } else if (is_nats_protocol(buf, count)) {
    protocol_message.protocol = kProtocolNATS;
  } else if (is_rocketmq_protocol(buf, count)) {
    protocol_message.protocol = kProtocolRocketMQ;
  }
  conn_info->prev_count = count;
  if (count == 4) {
    bpf_probe_read_user(conn_info->prev_buf, 4, buf);
  }
  return protocol_message;
}
#endif