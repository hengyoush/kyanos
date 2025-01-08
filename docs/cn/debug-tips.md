# Debug Tips

## 构建相关

注意每次修改 eBPF 相关代码后都需要使用 `make build-bpf`
重新生成一些 bpf 相关代码，然后再用 `make` 构建或者在 IDE 里调试。

使用 `kyanos-debug` 来构建带有调试信息的二进制文件, 以便更好地进行调试。

```sh
make kyanos-debug
```

## 日志相关

启动 kyanos 开启日志，日志分为几个模块可分别开启，5 为 debug 级别，默认是 warn 级别。如下是每个模块的日志选项：

| 参数                  | 含义                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------- |
| --agent-log-level     | 指定 agent 模块日志级别，主要是和 Agent 启动等相关的日志                                    |
| --bpf-event-log-level | 指定 bpf 事件日志级别，一些内核上报的和 syscall 层上报的事件会打印出来                      |
| --conntrack-log-level | 指定 conntrack 模块日志级别，一些连接相关的事件比如连接创建、协议推断、连接关闭等会打印出来 |
| --protocol-log-level  | 指定协议模块日志级别，主要是具体协议解析相关的日志                                          |
| --uprobe-log-level    | 指定 uprobe 模块日志级别，主要是和 ssl 探针相关的日志                                       |

比如如果你在调试协议解析相关部分的代码建议加上：`--bpf-event-log-level 5 --conntrack-log-level 5 --protocol-log-level 5`。

如果你碰到 eBPF 代码加载失败的情况，可以加上 `--agent-log-level 5`
日志打印一些 Agent 启动时的日志。

日志输出默认到/tmp 下，加上 `--debug-output`
选项可以让日志输出到标准输出，而且不再展示 tui 会展示的表格，抓取到的请求都会直接输出到控制台:

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

## eBPF 相关

协议推断代码可以通过 `bpf_printk`
打印日志调试，参考：https://nakryiko.com/posts/bpf-tips-printk/。

## IDE 调试相关

VSCODE 直接打开项目即可，.vscode/launch.json 添加配置如下：

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Launch file",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["watch", "--debug-output"]
    }
  ]
}
```

注意添加 `--debug-output` 参数。

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
