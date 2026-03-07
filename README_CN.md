![](docs/public/kyanos-demo.gif)

<div align="center">  
 
[![GitHub last commit](https://img.shields.io/github/last-commit/hengyoush/kyanos)](#) 
[![GitHub release](https://img.shields.io/github/v/release/hengyoush/kyanos)](#) 
[![Test](https://github.com/hengyoush/kyanos/actions/workflows/test.yml/badge.svg)](https://github.com/hengyoush/kyanos/actions/workflows/test.yml) 
[![Twitter](https://img.shields.io/twitter/url/https/x.com/kyanos.svg?style=social&label=Follow%20%40kyanos)](https://x.com/kyanos_github)

<a href="https://trendshift.io/repositories/12330" target="_blank">
<img src="https://trendshift.io/api/badge/repositories/12330" alt="hengyoush%2Fkyanos | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/>
</a>
[![Featured on Hacker News](https://hackerbadge.now.sh/api?id=42154583)](https://news.ycombinator.com/item?id=42154583)
<a href="https://hellogithub.com/repository/9e20a14a45dd4cd5aa169acf0e21fc45" target="_blank">
<img src="https://abroad.hellogithub.com/v1/widgets/recommend.svg?rid=9e20a14a45dd4cd5aa169acf0e21fc45&claim_uid=temso5CUu6fB7wb" alt="Featured｜HelloGitHub" style="width: 250px; height: 54px;" width="250" height="54" />
</a>

</div>

简体中文 | [English](./README.md)

## Table of Contents

- [Table of Contents](#table-of-contents)
- [🦜 What is kyanos](#-what-is-kyanos)
- [📦 Installation](#-installation)
- [🌰 Examples](#-examples)
- [❗ Requirements](#-requirements)
- [📝 Documentation](#-documentation)
- [🎯 How to get kyanos](#-how-to-get-kyanos)
- [⚙ Usage](#-usage)
- [🏠 How to Build](#-how-to-build)
- [Roadmap](#roadmap)
- [🤝 Feedback and Contributions](#-feedback-and-contributions)
- [🙇‍ Special Thanks](#-special-thanks)
- [🗨️ Contacts](#️-contacts)
- [Star History](#star-history)

## 🦜 What is kyanos

Kyanos 是一个网络流量采集和分析工具，它提供如下特性：

1. **强大的流量过滤功能**：不仅可以根据传统 IP/端口 等信息过滤，还支持根据：进程/容器、L7 协议信息、请求/响应字节数、耗时等过滤你想要的数据。

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

2. **强大的分析功能**： 和 tcpdump 只提供细粒度的抓包功能不同，kyanos 还支持以各种维度聚合抓取的数据包的指标信息，快速得到对排查问题最有用的关键数据。想象一下你的 HTTP 服务的带宽突然被打满，你该如何快速的分析是
   `哪些 ip` 的 `哪些请求` 造成的？  
   使用 kyanos 只需要一行命令：`kyanos stat http --bigresp` 即可找到发送给哪些远程 ip 的响应字节数最大，并且还能够发现请求响应的具体数据。
   ![kyanos find big response](docs/public/whatkyanos.gif)
3. **深入内核的耗时细节**：在实际业务场景中我们经常遇到远程服务慢查询问题，比如访问 Redis 请求较慢，但是
   **具体慢在哪里**
   在传统监控方式下很难给出确切答案。而 kyanos 提供了 请求/响应 到达网卡以及从 内核 Socket 缓冲区读取的内核埋点，并且以可视化的图形展示出来，你可以方便的判断是哪一个环节出现了问题。
   ![kyanos time detail](docs/public/timedetail.jpg)  
   如上所示，这是一个在容器内执行 `curl http://www.baidu.com`
   命令的耗时记录，你可以发现 kyanos 记录了请求经过容器网卡、宿主机网卡，响应经过宿主机网卡、容器网卡、Socket 缓冲区每个步骤的耗时。
4. **轻量级零依赖**：几乎 0 依赖，只需要单个二进制文件，一行命令，所有结果都展示在命令行中。
5. **SSL 流量自动解密**：kyanos 为你抓取的请求响应结果全部都是明文。

## 📦 Installation

### X-CMD

如果你是 [x-cmd](https://x-cmd.com/install/kyanos) 用户，可以使用以下命令安装它：

```bash
x install kyanos
```

## 🌰 Examples

**抓取 HTTP 流量并且获取耗时细节**

执行命令：

```bash
./kyanos watch http
```

演示结果如下：

![kyanos quick start watch http](docs/public/qs-watch-http.gif)

**抓取 Redis 流量获取耗时细节**

执行命令：

```bash
./kyanos watch redis
```

演示结果如下：

![kyanos quick start watch redis](docs/public/qs-redis.gif)

**找到 5s 内最慢的几个请求**

执行命令：

```bash
 ./kyanos stat --slow --time 5
```

演示结果如下：

![kyanos stat slow](docs/public/qs-stat-slow.gif)

## ❗ Requirements

Kyanos 当前支持 3.10(3.10.0-957 以上)及 4.14 以上版本内核(4.7 版本到 4.14 版本之间的后续计划支持)。

> 通过 `uname -r` 查看内核版本

## 📝 Documentation

[Chinese Document](https://kyanos.io/cn/)

## 🎯 How to get kyanos

你可以从 [release page](https://github.com/hengyoush/kyanos/releases)
中下载以静态链接方式编译的适用于 amd64 和 arm64 架构的二进制文件：

```bash
tar xvf kyanos_vx.x.x_linux_amd64.tar.gz
```

然后以 **root 权限** 执行如下命令：

```bash
sudo ./kyanos watch
```

如果显示了下面的表格：
![kyanos quick start success](docs/public/quickstart-success.png)
🎉 恭喜你，kyanos 启动成功了。

## ⚙ Usage

最简单的用法如下，抓取所有 kyanos 当前能够识别的协议

```bash
sudo ./kyanos watch
```

每个请求响应记录会记录在表格中的一行，每列记录这个请求的基本信息。你可以通过方向键或者 j/k 上下移动来选择记录：
![kyanos watch result](docs/public/watch-result.jpg)

按下 `enter` 进入详情界面：

![kyanos watch result detail](docs/public/watch-result-detail.jpg)

详情界面里第一部分是
**耗时详情**，每一个方块代表数据包经过的节点，比如这里有进程、网卡、Socket 缓冲区等。  
每个方块下面有一个耗时，这里的耗时指从上个节点到这个节点经过的时间。可以清楚的看到请求从进程发送到网卡，响应再从网卡复制到 Socket 缓冲区并且被进程读取的流程和每一个步骤的耗时。

第二部分是
**请求响应的具体内容**，分为 Request 和 Response 两部分，超过 1024 字节会截断展示。

抓取流量时一般会更有针对性，比如抓取 HTTP 流量：

```bash
./kyanos watch http
```

更进一步，你可能只想抓取某个 HTTP Path 的流量：

```bash
./kyanos watch http --path /abc
```

了解更多，请参考文档：[Kyanos Docs](kyanos.io)

## 🏠 How to Build

👉 [COMPILATION_CN.md](./COMPILATION_CN.md)

## Roadmap

Kyanos 的 Roadmap 展示了 Kyanos 未来的计划，如果你有功能需求，或者想提高某个特性的优先级，请在 GitHub 上提交 issue。

_1.6.0_

1. 支持 postgresql 协议解析。
2. 支持 HTTP2 协议。
3. 支持 DNS 协议。
4. 支持 GnuTLS 库解析加密流量。

## 🤝 Feedback and Contributions

> [!IMPORTANT]
>
> 如果你遇到了任何使用上的问题、bug 都可以在 issue 中提问。

## 🙇‍ Special Thanks

在开发 kyanos 的过程中，部分代码借用了以下项目：

- [eCapture](https://ecapture.cc/zh/)
- [pixie](https://github.com/pixie-io/pixie)
- [ptcpdump](https://github.com/mozillazg/ptcpdump)

## 🗨️ Contacts

如果你有更详细的问题需要咨询，可以用以下联系方式：

- **微信交流群：**:
  见：https://github.com/hengyoush/kyanos/issues/178。
- **我的邮箱：**: [hengyoush1@163.com](mailto:hengyoush1@163.com)。
- **我的 Blog：**: [http://blog.deadlock.cloud](http://blog.deadlock.cloud/)。

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=hengyoush/kyanos&type=Date)](https://star-history.com/#hengyoush/kyanos&Date)

[Back to top](#top)
