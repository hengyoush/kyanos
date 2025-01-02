# Debug Tips

## 构建相关

注意每次修改eBPF相关代码后都需要使用`make build-bpf`重新生成一些bpf相关代码，然后再用`make`构建或者在IDE里调试。

使用 `kyanos-debug` 来构建带有调试信息的二进制文件, 以便更好地进行调试。

```sh
make kyanos-debug
```

## 日志相关

启动kyanos开启日志，日志分为几个模块可分别开启，5为debug级别，默认是warn级别。如下是每个模块的日志选项：

| 参数                  | 含义                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------- |
| --agent-log-level     | 指定agent模块日志级别，主要是和Agent启动等相关的日志                                      |
| --bpf-event-log-level | 指定bpf事件日志级别，一些内核上报的和syscall层上报的事件会打印出来                        |
| --conntrack-log-level | 指定conntrack模块日志级别，一些连接相关的事件比如连接创建、协议推断、连接关闭等会打印出来 |
| --protocol-log-level  | 指定协议模块日志级别，主要是具体协议解析相关的日志                                        |
| --uprobe-log-level    | 指定uprobe模块日志级别，主要是和ssl探针相关的日志                                         |

比如如果你在调试协议解析相关部分的代码建议加上：`--bpf-event-log-level 5 --conntrack-log-level 5 --protocol-log-level 5`。

如果你碰到eBPF代码加载失败的情况，可以加上`--agent-log-level 5`日志打印一些Agent启动时的日志。

日志输出默认到/tmp下，加上 `--debug-output`
选项可以让日志输出到标准输出，而且不再展示tui会展示的表格，抓取到的请求都会直接输出到控制台:

```
WARN[0023] [ Request ]
GET /health HTTP/1.1
Host: :8080
User-Agent: Go-http-client/1.1
Accept-Encoding: gzip

[ Response ]
HTTP/1.1 200 OK
Date: Wed, 01 Jan 2025 16:20:20 GMT
Content-Length: 2
Content-Type: text/plain; charset=utf-8

OK

[conn] [pid=2252][local addr]=127.0.0.1:8080 [remote addr]=127.0.0.1:38664 [side]=server [ssl]=false
[total duration] = 0.423(ms)(start=2025-01-02 00:20:20.095, end=2025-01-02 00:20:20.095)
[read from sockbuf]=0.296(ms)
[process internal duration]=0.078(ms)
[syscall] [read count]=1 [read bytes]=92 [write count]=1 [write bytes]=118
```

> [!TIP]
>
> 调试协议解析相关代码时可以使用：`--bpf-event-log-level 5 --conntrack-log-level 5 --protocol-log-level 5 --debug-output`
> 选项就基本上足够了。

## 源码结构

```
> agent
  > analysis (聚合分析模块，stat命令用到)
  > conn （连接跟踪模块）
  > protocol（协议解析模块）
  > render（TUI渲染模块）
  > uprobe（uprobe相关主要是ssl探针）
> bpf
  > loader (bpf 程序加载逻辑)
  pktlatency.bpf.go (内核态核心代码，包括系统调用和内核部分的事件上报等逻辑)
  gotls.bpf.go (gotls探针相关)
  protocol_inference.h (协议推断相关)
  openssl* (openssl相关)
> cmd (命令行相关)
> common (一些工具类)
> docs (基于vitepress的文档)
```
