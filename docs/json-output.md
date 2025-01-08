# JSON Output Format <Badge type="tip" text="1.5.0" />

This document describes the JSON output format when using kyanos with the
`--json-output` flag.

## Usage

To output data in JSON format, use the `--json-output` flag with one of these
values:

```bash
# Output to terminal
kyanos watch --json-output=stdout

# Output to a file
kyanos watch --json-output=/path/to/custom.json
```

## Output Format

Each request-response pair is represented as a JSON object with the following
fields:

### Timing Information

| Field                               | Type   | Description                                                                                                                                                                                       |
| ----------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `start_time`                        | string | Start time of the request in RFC3339Nano format                                                                                                                                                   |
| `end_time`                          | string | End time of the request in RFC3339Nano format                                                                                                                                                     |
| `total_duration_ms`                 | number | Total duration of the request-response in milliseconds                                                                                                                                            |
| `black_box_duration_ms`             | number | For client side: Duration between request leaving and response arriving at the network interface.<br> For server side: Duration between request arriving at process and response leaving process. |
| `read_socket_duration_ms`           | number | Time spent reading from socket buffer                                                                                                                                                             |
| `copy_to_socket_buffer_duration_ms` | number | Time spent copying data to socket buffer                                                                                                                                                          |

### Connection Information

| Field         | Type    | Description                                        |
| ------------- | ------- | -------------------------------------------------- |
| `protocol`    | string  | Protocol name (e.g., "HTTP", "Redis", "MySQL")     |
| `side`        | string  | Whether this is a client or server side connection |
| `local_addr`  | string  | Local IP address                                   |
| `local_port`  | number  | Local port number                                  |
| `remote_addr` | string  | Remote IP address                                  |
| `remote_port` | number  | Remote port number                                 |
| `pid`         | number  | Process ID                                         |
| `is_ssl`      | boolean | Whether the connection is SSL/TLS encrypted        |

### Content Information

| Field                        | Type   | Description                          |
| ---------------------------- | ------ | ------------------------------------ |
| `req_size_bytes`             | number | Total size of request in bytes       |
| `resp_size_bytes`            | number | Total size of response in bytes      |
| `req_plain_text_size_bytes`  | number | Size of request plain text in bytes  |
| `resp_plain_text_size_bytes` | number | Size of response plain text in bytes |
| `request`                    | string | Formatted request content            |
| `response`                   | string | Formatted response content           |

### Event Details

| Field                 | Type  | Description                                      |
| --------------------- | ----- | ------------------------------------------------ |
| `req_syscall_events`  | array | Syscall events related to the request            |
| `resp_syscall_events` | array | Syscall events related to the response           |
| `req_nic_events`      | array | Network interface events related to the request  |
| `resp_nic_events`     | array | Network interface events related to the response |

## Example

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
