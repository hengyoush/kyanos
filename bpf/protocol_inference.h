#ifndef __P_INFER_H__
#define __P_INFER_H__

#include "pktlatency.h"

static __always_inline int32_t read_big_endian_int32(const char* buf) {
  int32_t length;
  bpf_probe_read(&length, sizeof(length), buf);
  return bpf_ntohl(length);
}

static __always_inline int16_t read_big_endian_int16(const char* buf) {
  int16_t val;
  bpf_probe_read(&val, sizeof(val), buf);
  return bpf_ntohs(val);
}

// Reference: https://kafka.apache.org/protocol.html#protocol_messages
// Request Header v0 => request_api_key request_api_version correlation_id
//     request_api_key => INT16
//     request_api_version => INT16
//     correlation_id => INT32
static __always_inline enum message_type_t infer_kafka_request(const char* buf) {
  // API is Kafka's terminology for opcode.
  static const int kNumAPIs = 62;
  static const int kMaxAPIVersion = 17;

  const int16_t request_API_key = read_big_endian_int16(buf);
  if (request_API_key < 0 || request_API_key > kNumAPIs) {
    // bpf_printk("kafka request API Key:%d, kNumAPIs:%d", request_API_key, kNumAPIs);
    return kUnknown;
  }

  const int16_t request_API_version = read_big_endian_int16(buf + 2);
  if (request_API_version < 0 || request_API_version > kMaxAPIVersion) {
    // bpf_printk("kafka request API version:%d, kMaxAPIVersion:%d, apikey:%d", request_API_version, kMaxAPIVersion, request_API_key);
    return kUnknown;
  }

  const int32_t correlation_id = read_big_endian_int32(buf + 4);
  if (correlation_id < 0) {
    // bpf_printk("kafka correlation_id:%d", correlation_id);
    return kUnknown;
  }
  return kRequest;
}

static __always_inline bool is_kafka_protocol(const char *buf, size_t count, size_t total_count, struct conn_info_t *conn_info) {
  size_t count_in_prev_buf = (size_t)read_big_endian_int32(conn_info->prev_buf);
  bool use_prev_buf =
        (conn_info->prev_count == 4) && (count_in_prev_buf == count || count_in_prev_buf == total_count);

  // bpf_printk("kafka count:%d, total_count:%d, use_prev_buf:%d", count, total_count, use_prev_buf);
  // bpf_printk("kafka prev_count:%d, prev_buf:%d", conn_info->prev_count, count_in_prev_buf);
  if (use_prev_buf) { 
    count += 4;
  }

  // length(4 bytes) + api_key(2 bytes) + api_version(2 bytes) + correlation_id(4 bytes)
  static const int kMinRequestLength = 12;
  if (count < kMinRequestLength) {
    // bpf_printk("kafka count:%d < kMinRequestLength:%d", count, kMinRequestLength);
    return kUnknown;
  }
  const int32_t message_size = use_prev_buf ? count : read_big_endian_int32(buf) + 4;

  // Enforcing count to be exactly message_size + 4 to mitigate misclassification.
  // However, this will miss long messages broken into multiple reads.
  if (message_size < 0 || (count != (size_t)message_size && total_count !=  (size_t)message_size)) {
    // bpf_printk( "kafka message_size:%d, count:%d, total_count:%d", message_size, count, total_count);
    return kUnknown;
  }

  const char* request_buf = use_prev_buf ? buf : buf + 4;
  enum message_type_t result = infer_kafka_request(request_buf);

  // Kafka servers read in a 4-byte packet length header first. The first packet in the
  // stream is used to infer protocol, but the header has already been read. One solution is to
  // add another perf_submit of the 4-byte header, but this would impact the instruction limit.
  // Not handling this case causes potential confusion in the parsers. Instead, we set a
  // prepend_length_header field if and only if Kafka has just been inferred for the first time
  // under the scenario described above. Length header is appended to user the buffer in user space.
  if (use_prev_buf && result == kRequest && conn_info->protocol == kProtocolUnknown) {
    // bpf_printk("kafka prepend_length_header");
    conn_info->prepend_length_header = true;
  }
  // bpf_printk("kafka result:%d", result);
  return result;
}

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

  // TODO: Consider adding more commands (0x00 to 0x1f).
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


// MongoDB protocol
static __inline enum message_type_t is_mongo_protocol(const char* old_buf, size_t count) {
  // Reference:
  // https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/#std-label-wp-request-opcodes.
  // Note: Response side inference for Mongo is not robust, and is not attempted to avoid
  // confusion with other protocols, especially MySQL.
  static const int32_t kOPUpdate = 2001;
  static const int32_t kOPInsert = 2002;
  static const int32_t kReserved = 2003;
  static const int32_t kOPQuery = 2004;
  static const int32_t kOPGetMore = 2005;
  static const int32_t kOPDelete = 2006;
  static const int32_t kOPKillCursors = 2007;
  static const int32_t kOPCompressed = 2012;
  static const int32_t kOPMsg = 2013;

  static const int32_t kMongoHeaderLength = 16;

  if (count < kMongoHeaderLength) {
    return kUnknown;
  }

  char buf[17] = {};
  bpf_probe_read_user(buf, 17, old_buf);

  int32_t* buf4 = (int32_t*)buf;
  int32_t message_length = buf4[0];

  if (message_length < kMongoHeaderLength) {
    return kUnknown;
  }

  int32_t request_id = buf4[1];

  if (request_id < 0) {
    return kUnknown;
  }

  int32_t response_to = buf4[2];
  int32_t opcode = buf4[3];

  if (opcode == kOPUpdate || opcode == kOPInsert || opcode == kReserved || opcode == kOPQuery ||
      opcode == kOPGetMore || opcode == kOPDelete || opcode == kOPKillCursors ||
      opcode == kOPCompressed || opcode == kOPMsg) {
    if (response_to == 0) {
      return kRequest;
    }
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
  } else {
    return kUnknown;
  }
  return kRequest;
}


static __always_inline struct protocol_message_t infer_protocol(const char *buf, size_t count, size_t total_count, struct conn_info_t *conn_info) {
  struct protocol_message_t protocol_message;
  protocol_message.protocol = kProtocolUnknown;
  protocol_message.type = kUnknown;
  conn_info->prepend_length_header = false;

  if ((protocol_message.type = is_http_protocol(buf, count)) != kUnknown) {
    protocol_message.protocol = kProtocolHTTP;
  } else if ((protocol_message.type = is_mongo_protocol(buf, count)) != kUnknown)  {
    protocol_message.protocol = kProtocolMongo;
  } else if ((protocol_message.type = is_mysql_protocol(buf, count, conn_info)) != kUnknown)  {
    protocol_message.protocol = kProtocolMySQL;
  } else if ((protocol_message.type = is_rocketmq_protocol(buf, count)) != kUnknown) {
    protocol_message.protocol = kProtocolRocketMQ;
  } else if ((protocol_message.type = is_kafka_protocol(buf, count, total_count, conn_info)) != kUnknown) {
    protocol_message.protocol = kProtocolKafka;
  } else if (is_redis_protocol(buf, count)) {
    protocol_message.protocol = kProtocolRedis;
  }
  conn_info->prev_count = count;
  if (count == 4) {
    bpf_probe_read(conn_info->prev_buf, 4, buf);
  }
  return protocol_message;
}
#endif
