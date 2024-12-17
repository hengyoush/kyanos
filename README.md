# kyanos


![](docs/public/kyanos-demo.gif)
<div align="center">  
 
[![GitHub last commit](https://img.shields.io/github/last-commit/hengyoush/kyanos)](#) 
[![GitHub release](https://img.shields.io/github/v/release/hengyoush/kyanos)](#) 
[![Test](https://github.com/hengyoush/kyanos/actions/workflows/test.yml/badge.svg)](https://github.com/hengyoush/kyanos/actions/workflows/test.yml) 
[![Twitter](https://img.shields.io/twitter/url/https/x.com/kyanos.svg?style=social&label=Follow%20%40kyanos)](https://x.com/kyanos_github)  

<a href="https://trendshift.io/repositories/12330" target="_blank"><img src="https://trendshift.io/api/badge/repositories/12330" alt="hengyoush%2Fkyanos | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>
[![Featured on Hacker News](https://hackerbadge.now.sh/api?id=42154583)](https://news.ycombinator.com/item?id=42154583)
<a href="https://hellogithub.com/repository/9e20a14a45dd4cd5aa169acf0e21fc45" target="_blank"><img src="https://abroad.hellogithub.com/v1/widgets/recommend.svg?rid=9e20a14a45dd4cd5aa169acf0e21fc45&claim_uid=temso5CUu6fB7wb" alt="Featured｜HelloGitHub" style="width: 250px; height: 54px;" width="250" height="54" /></a>

</div>

[简体中文](./README_CN.md) | English 


- [English Document](https://kyanos.io/)

## Table of Contents
- [What is kyanos](#-what-is-kyanos)
- [Examples](#-examples)
- [Requirements](#-requirements)
- [How to get kyanos](#-how-to-get-kyanos)
- [Documentation](#-documentation)
- [Usage](#-usage)
- [How to build](#-how-to-build)
- [Feedback and Contributions](#-feedback-and-contributions)
- [Special Thanks](#-special-thanks)
- [Contacts](#%EF%B8%8F-contacts)

## What is kyanos
Kyanos is an **eBPF-based** network issue analysis tool that enables you to capture network requests, such as HTTP, Redis, and MySQL requests.   
It also helps you analyze abnormal network issues and quickly troubleshooting without the complex steps of packet capturing, downloading, and analysis.

1. **Powerful Traffic Filtering**: Not only can filter based on traditional IP/port information, can also filter by process/container, L7 protocol information, request/response byte size, latency, and more.

```bash
# Filter by pid
./kyanos watch --pids 1234
# Filter by container id
./kyanos watch --container-id abc
# Filter by Redis key
./kyanos watch redis --keys my-key1,my-key2
# Filter by response byte size
./kyanos watch --resp-size 10000
```

2. **Advanced Analysis Capabilities** : Unlike tcpdump, which only provides fine-grained packet capture, Kyanos supports aggregating captured packet metrics across various dimensions, quickly providing the critical data most useful for troubleshooting.  
Imagine if the bandwidth of your HTTP service is suddenly maxed out—how would you quickly analyze `which IPs` and `which  requests` are causing it?  
With Kyanos, you just need one command: `kyanos stat http --bigresp` to find the largest response byte sizes sent to remote IPs and view specific data on request and response metrics.  
![kyanos find big response](docs/public/whatkyanos.gif)

3. **In-Depth Kernel-Level Latency Details**: In real-world, slow queries to remote services like Redis can be challenging to diagnose precisely. Kyanos provides kernel trace points from the arrival of requests/responses at the network card to the kernel socket buffer, displaying these details in a visual format. This allows you to identify exactly which stage is causing delays.

![kyanos time detail](docs/public/timedetail.jpg) 

4. **Lightweight and Dependency-Free**: Almost zero dependencies—just a single binary file and one command, with all results displayed in the command line.

5. **Automatic SSL Traffic Decryption** : All captured requests and responses are presented in plaintext.

## Examples

**Capture HTTP Traffic with Latency Details**  

Run the command:
```bash
./kyanos watch http
```
The result is as follows:

![kyanos quick start watch http](docs/public/qs-watch-http.gif)


**Capture Redis Traffic with Latency Details**  

Run the command:
```bash
./kyanos watch redis
```
The result is as follows:

![kyanos quick start watch redis](docs/public/qs-redis.gif)

**Identify the Slowest Requests in the Last 5 Seconds**

Run the command:
```bash
 ./kyanos stat --slow --time 5 
```
The result is as follows:

![kyanos stat slow](docs/public/qs-stat-slow.gif)

## ❗ Requirements

Kyanos currently supports kernel versions 3.10(from 3.10.0-957) and 4.14 or above (with plans to support versions between 4.7 and 4.14 in the future).  
> You can check your kernel version using `uname -r`.


## 🎯 How to get kyanos 

You can download a statically linked binary compatible with amd64 and arm64 architectures from the [release page](https://github.com/hengyoush/kyanos/releases):

```bash
tar xvf kyanos_vx.x.x_linux_amd64.tar.gz
```

Then, run kyanos with **root privilege**:
```bash
sudo ./kyanos watch 
```

If the following table appears:
![kyanos quick start success](docs/public/quickstart-success.png)
🎉 Congratulations! Kyanos has started successfully.

## 📝 Documentation

[English Document](https://kyanos.io/)

## ⚙ Usage

The simplest usage captures all protocols currently supported by Kyanos:

```bash
sudo ./kyanos watch
```

Each request-response record is stored as a row in a table, with each column capturing basic information about that request. You can use the arrow keys or `j/k` to move up and down through the records:
![kyanos watch result](docs/public/watch-result.jpg)  

Press `Enter` to access the details view:

![kyanos watch result detail](docs/public/watch-result-detail.jpg)  

In the details view, the first section shows **Latency Details**. Each block represents a "node" that the data packet passes through, such as the process, network card, and socket buffer.  
Each block includes a time value indicating the time elapsed from the previous node to this node, showing the process flow from the process sending the request to the network card, to the response being copied to the socket buffer, and finally read by the process, with each step’s duration displayed.

The second section provides **Detailed Request and Response Content**, split into Request and Response parts, and truncates content over 1024 bytes.

For targeted traffic capture, such as HTTP traffic:

```bash
./kyanos watch http
```

You can narrow it further to capture traffic for a specific HTTP path:

```bash
./kyanos watch http --path /abc 
```

Learn more: [Kyanos Docs](https://kyanos.io/)

## 🏠 How to build

👉 [COMPILATION.md](./COMPILATION.md)

## Roadmap
The Kyanos Roadmap shows the future plans for Kyanos. If you have feature requests or want to prioritize a specific feature, please submit an issue on GitHub.

_1.5.0_

1. Support for openssl 3.4.0
2. Support for parsing ipip packets
3. Support for filtering data based on process name
4. Support for postgresql protocol parsing
5. Support for kafka protocol parsing
6. Full support for ipv6


## 🤝 Feedback and Contributions
> [!IMPORTANT]
> If you encounter any issues or bugs while using the tool, please feel free to ask questions in the issue tracker.

## 🙇‍ Special Thanks
During the development of kyanos, some code was borrowed from the following projects:
- [eCapture](https://ecapture.cc/zh/)
- [pixie](https://github.com/pixie-io/pixie)
- [ptcpdump](https://github.com/mozillazg/ptcpdump)

## 🗨️ Contacts
For more detailed inquiries, you can use the following contact methods:
- **Twitter:** [https://x.com/kyanos_github](https://x.com/kyanos_github)
- **My Email:** [hengyoush1@163.com](mailto:hengyoush1@163.com)
- **My Blog:** [http://blog.deadlock.cloud](http://blog.deadlock.cloud/)

[Back to top](#top)
