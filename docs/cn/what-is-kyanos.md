---
next:
  text: '快速开始'
  link: './quickstart'
prev: false
---
# Kyanos 是什么？{#what-is-kyanos}

Kyanos 是一个基于eBPF的网络问题分析工具，你可以用它来抓取业务请求，比如HTTP请求、Redis请求、MYSQL请求等，还可以帮你分析异常链路，快速排查业务故障，而不需要繁琐的抓包，下载，分析等步骤，并且拥有良好的兼容性，大多数情况下无需任何依赖一行命令即可开始分析。

## 你为什么应该使用 Kyanos?
> 现在已经有很多网络排查工具了比如tcpdump，iftop，netstat等，那么kyanos有什么优势呢？

### 传统的tcpdump抓包排查的缺点  

1. 难以根据协议特定信息过滤，以 HTTP 协议为例，很难做到根据特定 HTTP Path 抓包，必须依赖 wireshark/tshark 这类工具进行二次过滤。
2. 难以根据数据包收发的进程/容器等过滤，尤其在一个机器上部署多个进程/容器的时候，只需要抓取某个业务进程的数据包。
3. 排查效率较低，一般排查流程：首先是进入生产环境使用 tcpdump 抓包生成 pcap 文件，然后需要下载到本地再通过 wireshark 工具分析，往往消耗了大量时间。
4. 较弱的分析能力，tcpdump 只提供底层的抓包能力，几乎不具备高阶的分析能力，必须要和 wireshark 搭配使用，而传统的网络监控工具比如 iftop 和 nestat 只能提供粗粒度的监控，想要排查根因很难。
5. 加密的流量比如使用SSL协议的请求无法看到明文。


### kyanos能为你带来的

1. **强大的流量过滤功能**：不仅可以根据传统 IP/端口 等信息过滤，还支持根据：进程/容器、L7协议信息、请求/响应字节数、耗时等过滤你想要的数据。
```bash
# 根据 pid 过滤
./kyanos watch --pids 1234
# 根据容器 id 过滤
./kyanos watch --container-id abc
# 根据 redis 的 key 过滤
./kyanos watch redis --keys my-key1,my-key2
# 根据响应字节数过滤
./kyanos watch --resp-size 10000
```
2. **强大的分析功能**： 和 tcpdump 只提供细粒度的抓包功能不同，kyanos 还支持以各种维度聚合抓取的数据包的指标信息，快速得到对排查问题最有用的关键数据。想象一下你的 HTTP 服务的带宽突然被打满，你该如何快速的分析是 `哪些 ip` 的 `哪些请求` 造成的？  
使用 kyanos 只需要一行命令：`kyanos stat http --bigresp` 即可找到发送给哪些远程 ip 的响应字节数最大，并且还能够发现请求响应的具体数据。
![kyanos find big response](/whatkyanos.gif)
3. **深入内核的耗时细节**：在实际业务场景中我们经常遇到远程服务慢查询问题，比如访问 Redis 请求较慢，但是 **具体慢在哪里** 在传统监控方式下很难给出确切答案。而 kyanos 提供了 请求/响应 到达网卡以及从 内核Socket 缓冲区读取的内核埋点，并且以可视化的图形展示出来，你可以方便的判断是哪一个环节出现了问题。
![kyanos time detail](/timedetail.jpg)   
如上所示，这是一个在容器内执行 `curl http://www.baidu.com` 命令的耗时记录，你可以发现 kyanos 记录了请求经过容器网卡、宿主机网卡，响应经过宿主机网卡、容器网卡、Socket缓冲区每个步骤的耗时。
4. **轻量级零依赖**：几乎 0 依赖，只需要单个二进制文件，一行命令，所有结果都展示在命令行中。
5. **SSL流量自动解密**：kyanos 为你抓取的请求响应结果全部都是明文。


## 什么时候你会使用 kyanos {#use-cases}

- **抓取请求响应**

kyanos 提供了 watch 命令可以帮助你过滤抓取各种流量，它支持根据进程id、容器id、容器 name、pod name 以及 IP、端口过滤，也支持根据协议特定的字段过滤，比如HTTP PATH，Redis的命令以及key过滤。抓取的流量不仅仅包含请求响应的具体内容，还包括耗时的细节，比如请求从系统调用到网卡，再到响应从网卡到socket缓冲区再到进程去读取它，这些耗时细节你全部都能得到。

- **分析异常链路**

kyanos 的 stat 命令可以帮你快速找到异常链路，stat 命令支持根据多种维度聚合，比如kyanos支持根据远程ip聚合，让你可以快速分析出是哪一个远程ip更慢；另外kyanos支持各种指标的统计，比如请求响应耗时、请求响应大小等。结合以上两点，80%的业务网络异常问题都可以快速定位。

- **全局依赖分析** <Badge type="tip" text="beta" />

有时候你想知道整个机器依赖哪些外部资源，kyanos 提供了 overview 命令帮你一键抓取整个机器依赖的外部资源及其耗时情况。

## 基础示例

**抓取 HTTP 流量并且获取耗时细节**  

执行命令：
```bash
./kyanos watch http
```
演示结果如下：

![kyanos quick start watch http](/qs-watch-http.gif)


**抓取 Redis 流量获取耗时细节**  

执行命令：
```bash
./kyanos watch redis
```
演示结果如下：

![kyanos quick start watch redis](/qs-redis.gif)

**找到5s内最慢的几个请求**

执行命令：
```bash
 ./kyanos stat --slow --time 5 
```
演示结果如下：

![kyanos stat slow](/qs-stat-slow.gif)

