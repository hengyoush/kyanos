---
prev:
  text: "5分钟学会使用kyanos"
  link: "./how-to"
next:
  text: "Stat 使用方法"
  link: "./stat"
---

# 抓取请求响应和耗时细节

你可以使用 watch 命令收集你感兴趣的请求响应流量，具体来说，你能够通过 watch 命令：

- 查看请求响应的具体内容。
- 查看耗时细节：包括请求到达网卡、响应到达网卡、响应到达 Socket 缓冲区、应用进程读取响应这几个重要的时间点。

从一个最简单的例子开始：

```bash
kyanos watch
```

由于没有指定任何过滤条件，因此 kyanos 会尝试采集所有它能够解析的流量，当前 kyanos 支持三种应用层协议的解析：HTTP、Redis 和 MySQL。

当你执行这行命令之后，你会看到一个表格：
![kyanos watch result](/watch-result.jpg)

> [!TIP]
>
> watch 默认采集 100 条请求响应记录，你可以通过 `--max-records` 选项来指定

每一列的含义如下：

| 列名称         | 含义                                                                                                                                     | 示例                               |
| :------------- | :--------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| id             | 表示序号                                                                                                                                 | 1                                  |
| Connection     | 表示这次请求响应的连接                                                                                                                   | "10.0.4.9:44526 => 169.254.0.4:80" |
| Proto          | 请求响应的协议                                                                                                                           | "HTTP"                             |
| TotalTime      | 这次请求响应的总耗时，单位毫秒                                                                                                           | 100                                |
| ReqSize        | 请求大小，单位 bytes                                                                                                                     | 512                                |
| RespSize       | 响应大小，单位 bytes                                                                                                                     | 1024                               |
| Net/Internal   | 如果这是本地发起的请求，含义为网络耗时; 如果是作为服务端接收外部请求，含义为本地进程处理的内部耗时                                       | 50                                 |
| ReadSocketTime | 如果这是本地发起的请求，含义为从内核 Socket 缓冲区读取响应的耗时; 如果是作为服务端接收外部请求，含义从内核 Socket 缓冲区读取请求的耗时。 | 30                                 |

按下数字键可以排序对应的列。按 `"↑"` `"↓"` 或者 `"k"` `"j"`
可以上下移动选择表格中的记录。按下 enter 进入这次请求响应的详细界面：

![kyanos watch result detail](/watch-result-detail.jpg)

详情界面里第一部分是
**耗时详情**，每一个方块代表数据包经过的节点，比如这里有进程、网卡、Socket 缓冲区等。  
每个方块下面有一个耗时，这里的耗时指从上个节点到这个节点经过的时间。可以清楚的看到请求从进程发送到网卡，响应再从网卡复制到 Socket 缓冲区并且被进程读取的流程和每一个步骤的耗时。

第二部分是
**请求响应的具体内容**，分为 Request 和 Response 两部分，超过 1024 字节会截断展示（通过
`--max-print-bytes` 选项可以调整这个限制）。

## JSON 输出 <Badge type="tip" text="1.5.0" />

如果你需要以编程方式处理采集到的数据，可以使用 `--json-output`
参数将结果输出为 JSON 格式：

```bash
# 输出到终端
kyanos watch --json-output=stdout

# 输出到文件
kyanos watch --json-output=/path/to/custom.json
```

JSON 输出中包含每个请求-响应对的详细信息，包括：

- 请求和响应的时间戳
- 连接详情（地址和端口）
- 协议特定信息
- 详细的耗时指标
- 请求和响应内容

完整的 JSON 输出格式规范，请参考 [JSON 输出格式](./json-output.md) 文档。

## 如何发现你感兴趣的请求响应 {#how-to-filter}

默认 kyanos 会抓取所有它目前支持协议的请求响应，在很多场景下，我们需要更加精确的过滤，比如想要发送给某个远程端口的请求，抑或是某个进程或者容器的关联的请求，又或者是某个 Redis 命令或者 HTTP 路径相关的请求。下面介绍如何使用 kyanos 的各种选项找到我们感兴趣的请求响应。

### 根据 IP 端口过滤

kyanos 支持根据 IP 端口等三/四层信息过滤，可以指定以下选项：

| 过滤条件       | 命令行 flag    | 示例                                                                                            |
| :------------- | :------------- | :---------------------------------------------------------------------------------------------- |
| 连接的本地端口 | `local-ports`  | `--local-ports 6379,16379` <br> 只观察本地端口为 6379 和 16379 的连接上的请求响应               |
| 连接的远程端口 | `remote-ports` | `--remote-ports 6379,16379` <br> 只观察远程端口为 6379 和 16379 的连接上的请求响应              |
| 连接的远程 ip  | `remote-ips`   | `--remote-ips  10.0.4.5,10.0.4.2` <br> 只观察远程 ip 为 10.0.4.5 和 10.0.4.2 的连接上的请求响应 |
| 客户端/服务端  | `side`         | `--side  client/server` <br> 只观察作为客户端发起连接/作为服务端接收连接时的请求响应            |

### 根据进程/容器过滤 {#filter-by-container}

| 过滤条件      | 命令行 flag      | 示例                                                                  |
| :------------ | :--------------- | :-------------------------------------------------------------------- |
| 进程 pid 列表 | `pids`           | `--pids 12345,12346` 多个 pid 按逗号分隔                              |
| 进程名称      | `comm`           | `--comm 'redis-cli'`                                                  |
| 容器 id       | `container-id`   | `--container-id xx`                                                   |
| 容器名称      | `container-name` | `--container-name foobar`                                             |
| k8s pod 名称  | `pod-name`       | `--pod-name nginx-7bds23212-23s1s.default` <br> 格式： NAME.NAMESPACE |

值得一提的是，kyanos 也会显示容器网卡和宿主机网卡之间的耗时：
![kyanos time detail](/timedetail.jpg)

### 根据请求响应的一般信息过滤

| 过滤条件       | 命令行 flag | 示例                                                       |
| :------------- | :---------- | :--------------------------------------------------------- |
| 请求响应耗时   | `latency`   | `--latency 100` 只观察耗时超过 100ms 的请求响应            |
| 请求大小字节数 | `req-size`  | `--req-size 1024` 只观察请求大小超过 1024bytes 的请求响应  |
| 响应大小字节数 | `resp-size` | `--resp-size 1024` 只观察响应大小超过 1024bytes 的请求响应 |

### 根据协议特定信息过滤

你可选择只采集某种协议的请求响应，通过在 watch 后面加上具体的协议名称，当前支持：

- `http`
- `redis`
- `mysql`

比如：`kyanos watch http --path /foo/bar`, 下面是每种协议你可以使用的选项。

#### HTTP 协议过滤

| 过滤条件       | 命令行 flag   | 示例                                                                      |
| :------------- | :------------ | :------------------------------------------------------------------------ |
| 请求 Path      | `path`        | `--path /foo/bar ` 只观察 path 为/foo/bar 的请求                          |
| 请求 Path 前缀 | `path-prefix` | `--path-prefix /foo/bar ` 只观察 path 前缀为/foo/bar 的请求               |
| 请求 Path 正则 | `path-regex`  | `--path-regex "\/foo\/bar\/.*" ` 只观察 path 匹配 `\/foo\/bar\/.*` 的请求 |
| 请求 Host      | `host`        | `--host www.baidu.com ` 只观察 Host 为 www.baidu.com 的请求               |
| 请求方法       | `method`      | `--method GET` 只观察方法为 GET                                           |

#### Redis 协议过滤

| 过滤条件      | 命令行 flag  | 示例                                                  |
| :------------ | :----------- | :---------------------------------------------------- |
| 请求命令      | `command`    | `--command GET,SET ` 只观察请求命令为 GET 和 SET      |
| 请求 Key      | `keys`       | `--keys foo,bar ` 只观察请求 key 为 foo 和 bar        |
| 请求 key 前缀 | `key-prefix` | `--method foo:bar ` 只观察请求的 key 前缀为 foo\: bar |

#### RocketMQ 协议过滤 <Badge type="tip" text="1.5.0" />

| 过滤条件 | 命令行 flag     | 示例                                                                    |
| :------- | :-------------- | :---------------------------------------------------------------------- |
| 请求代码 | `request-codes` | `--request-codes 10,11` 只观察请求代码为 10 和 11 的                    |
| 语言     | `languages`     | `--languages Java,Go ` 只观察使用 Java 和 Go 编写的应用程序发出的请求。 |

> 有关请求代码的含义和值，请参阅
> [这里](https://github.com/apache/rocketmq/blob/develop/remoting/src/main/java/org/apache/rocketmq/remoting/protocol/RequestCode.java)。

> 更多支持的语言，请参阅
> [这里](https://github.com/apache/rocketmq/blob/develop/remoting/src/main/java/org/apache/rocketmq/remoting/protocol/LanguageCode.java)。

#### MYSQL 协议过滤

> 已支持 MySQL 协议抓取，根据条件过滤仍在实现中...

---

> [!TIP]
>
> 所有上述选项均可以组合使用，比如：`./kyanos watch redis --keys foo,bar --remote-ports 6379 --pid 12345`
