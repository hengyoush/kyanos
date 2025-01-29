# JSON 输出格式 <Badge type="tip" text="preview" />

本文档描述了使用 kyanos 的 `--json-output` 参数时的 JSON 输出格式。

## 使用方法

使用 `--json-output` 参数输出 JSON 格式数据，可以指定以下值：

```bash
# 输出到终端
kyanos watch --json-output=stdout

# 输出到文件
kyanos watch --json-output=/path/to/custom.json
```

## 输出格式

每个请求-响应对都表示为一个 JSON 对象，包含以下字段：

### 时间信息

| 字段                                | 类型   | 描述                                                                                                             |
| ----------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------- |
| `start_time`                        | string | 请求开始时间，RFC3339Nano 格式                                                                                   |
| `end_time`                          | string | 请求结束时间，RFC3339Nano 格式                                                                                   |
| `total_duration_ms`                 | number | 请求-响应总耗时，单位毫秒                                                                                        |
| `black_box_duration_ms`             | number | 对于客户端：请求离开和响应到达网络接口之间的持续时间 <br> 对于服务器端：请求到达进程和响应离开进程之间的持续时间 |
| `read_socket_duration_ms`           | number | 从 socket 缓冲区读取数据的耗时                                                                                   |
| `copy_to_socket_buffer_duration_ms` | number | 复制数据到 socket 缓冲区的耗时                                                                                   |

### 连接信息

| 字段          | 类型    | 描述                                    |
| ------------- | ------- | --------------------------------------- |
| `protocol`    | string  | 协议名称（如 "HTTP"、"Redis"、"MySQL"） |
| `side`        | string  | 连接的角色（客户端或服务端）            |
| `local_addr`  | string  | 本地 IP 地址                            |
| `local_port`  | number  | 本地端口号                              |
| `remote_addr` | string  | 远程 IP 地址                            |
| `remote_port` | number  | 远程端口号                              |
| `pid`         | number  | 进程 ID                                 |
| `is_ssl`      | boolean | 是否是 SSL/TLS 加密连接                 |

### 内容信息

| 字段                         | 类型   | 描述                   |
| ---------------------------- | ------ | ---------------------- |
| `req_size_bytes`             | number | 请求总大小，单位字节   |
| `resp_size_bytes`            | number | 响应总大小，单位字节   |
| `req_plain_text_size_bytes`  | number | 请求明文大小，单位字节 |
| `resp_plain_text_size_bytes` | number | 响应明文大小，单位字节 |
| `request`                    | string | 格式化后的请求内容     |
| `response`                   | string | 格式化后的响应内容     |

### 事件详情

| 字段                  | 类型  | 描述                   |
| --------------------- | ----- | ---------------------- |
| `req_syscall_events`  | array | 请求相关的系统调用事件 |
| `resp_syscall_events` | array | 响应相关的系统调用事件 |
| `req_nic_events`      | array | 请求相关的网卡事件     |
| `resp_nic_events`     | array | 响应相关的网卡事件     |

## 示例

```json
{
  "start_time": "2024-01-01T12:00:00.123456789Z",
  "end_time": "2024-01-01T12:00:00.234567890Z",
  "protocol": "HTTP",
  "side": "client",
  "local_addr": "127.0.0.1",
  "local_port": 54321,
  "remote_addr": "192.168.1.1",
  "remote_port": 80,
  "pid": 12345,
  "is_ssl": false,
  "total_duration_ms": 111.111111,
  "black_box_duration_ms": 50.505050,
  "read_socket_duration_ms": 30.303030,
  "copy_to_socket_buffer_duration_ms": 20.202020,
  "req_size_bytes": 256,
  "resp_size_bytes": 1024,
  "req_plain_text_size_bytes": 256,
  "resp_plain_text_size_bytes": 1024,
  "request": "GET /api/v1/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"success\"}",
  "req_syscall_events": [...],
  "resp_syscall_events": [...],
  "req_nic_events": [...],
  "resp_nic_events": [...]
}
```
