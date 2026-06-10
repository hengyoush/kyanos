---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Kyanos"
  text: "A Simple & Powerful Network Tracing Tool"
  tagline: 秒级分析定位网络问题
  image:
    src: /kyanos.png
    alt: Kyanos
  actions:
    - theme: brand
      text: What is Kyanos?
      link: ./what-is-kyanos
    - theme: alt
      text: Quickstart
      link: ./quickstart
    - theme: alt
      text: Star me at Github!
      link: https://github.com/hengyoush/kyanos

features:
  - icon: 🚀
    title: 使用简单
    details: 聚焦于7层协议，只需一条命令即可快速查看应用的网络性能，包括 HTTP、Redis、MySQL、Kafka、MongoDB、RocketMQ、DNS 等服务的网络延迟和数据传输大小
    link: ./how-to
    linkText: Learn how to use kyanos
  - icon: 🎯️
    title: 高级数据过滤
    details:
      支持根据协议字段（如HTTP的Path或Redis的Command）过滤数据，以及根据进程PID、容器ID、K8s
      Pod名称等多维度筛选数据，提供更精确的问题定位。
    link: ./watch#how-to-filter
    linkText: Learn how to filter traffic
  - icon: 📈️
    title: 强大的聚合分析
    details: 支持根据远程IP、协议等维度自动聚合数据，快速获取特定信息，如特定IP的HTTP路径耗时情况。
    link: ./stat
    linkText: Learn how to analysis traffic
  - icon: 💻️
    title: 容器网络监控
    details: 在容器化环境中，能够统计数据包从容器网卡到宿主机网卡的耗时。
    link: ./watch#filter-by-container
    linkText: Capture container traffic
  - icon: 📊️
    title: 直观的用户界面
    details: 基于命令行就地分析，提供可视化的输出，无需复杂的文件下载和分析步骤。
    link: ./how-to
    linkText: Learn how to use kyanos
  - icon: 🌐️
    title: 轻量级与兼容性
    details: Kyanos作为一个网络问题排查工具，不依赖于任何外部依赖，能够在从3.10版本到最新版本的内核上运行
    link: ./quickstart#prerequire
    linkText: Install kyanos
---
