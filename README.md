# kyanos
![GitHub Release](https://img.shields.io/badge/language-golang-blue) ![GitHub Release](https://img.shields.io/badge/os-linux-239120) [![GitHub last commit](https://img.shields.io/github/last-commit/hengyoush/kyanos)](#) [![GitHub release](https://img.shields.io/github/v/release/hengyoush/kyanos)](#) [![Free](https://img.shields.io/badge/free_for_non_commercial_use-brightgreen)](#-license)

⭐ Star us on GitHub — it motivates us a lot!

[![Share](https://img.shields.io/badge/share-000000?logo=x&logoColor=white)](https://x.com/intent/tweet?text=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/hengyoush/kyanos%20%23OpenIDConnect%20%23Security%20%23Authentication)
[![Share](https://img.shields.io/badge/share-1877F2?logo=facebook&logoColor=white)](https://www.facebook.com/sharer/sharer.php?u=https://github.com/hengyoush/kyanos)
[![Share](https://img.shields.io/badge/share-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/sharing/share-offsite/?url=https://github.com/hengyoush/kyanos)
[![Share](https://img.shields.io/badge/share-FF4500?logo=reddit&logoColor=white)](https://www.reddit.com/submit?title=Check%20out%20this%20project%20on%20GitHub:%20https://github.com/hengyoush/kyanos)
[![Share](https://img.shields.io/badge/share-0088CC?logo=telegram&logoColor=white)](https://t.me/share/url?url=https://github.com/hengyoush/kyanos&text=Check%20out%20this%20project%20on%20GitHub)

## Table of Contents
- [Motivation](#-Motivation)
- [Certification](#-certification)
- [How to Build](#-how-to-build)
- [Documentation](#-documentation)
- [Feedback and Contributions](#-feedback-and-contributions)
- [License](#-license)
- [Contacts](#%EF%B8%8F-contacts)

## 🚀 Motivation

你有没有遇到过这样的问题：你负责一个业务服务，突然有一天你的上游气势汹汹找你，问你的服务接口为什么调用超时，然而你查看监控，发现自己服务的接口耗时正常，接下来你们开始互相扯皮甩锅，可谁也记不起来问题有没有解决。

反过来，你调用下游接口超时，但对方监控显示并没有超时，于是又开始新的扯皮流程，不同的是你站在了另一边...

## 🎓 What is kyanos

kyanos正是为了快速排查这类问题诞生的，它是一个面向程序员的网络问题分析工具。和其他网络分析工具不同，它不仅可以细粒度的观察每一个应用层请求响应的具体结果及其在内核中的耗时, 也可以粗粒度的观察主机上连接的整体情况，而这些全部都是基于7层协议的，kyanos支持针对每种协议做过滤，也就是说你可以站在请求响应的视角排查网络问题，排除其他不相干问题的干扰。

下面的这个例子展示其抓取主机上耗时超过200ms的HTTP请求响应，并将其在内核中以及网络中的重要阶段的耗时打印出来：

## 🔍 Watch
作为最基本的能力，kyanos支持多种协议的流量抓取，同时支持根据响应大小/响应耗时/应用层协议以及应用层协议特定的条件（比如HTTP的Path、Method等）过滤。
支持协议及其过滤条件如下：

支持通用过滤条件（协议无关）如下：



## 📈 Analysis
仅有这些仍然不足以让kyanos成为一个强大的工具，kyanos还具备非常多的自动分析能力。
比如说：一行命令：
你可以仅仅给出一个本地端口，kyanos还可以帮你找到请求次数最高/请求数据最大/响应数据最大/耗时最长的客户端及其请求响应数据。
如下是例子：TODO

## 🎯 How to get kyanos


## 🤝 Feedback and Contributions

## 🗨️ Contacts