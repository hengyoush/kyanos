---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Kyanos"
  text: "A Simple & Powerful Network Tracing Tool"
  tagline: Tackle network troubles in just 30 seconds!
  image:
    src: /kyanos.png
    alt: SnowAdmin
  actions:
    - theme: brand
      text: What is Kyanos?
      link: /markdown-examples
    - theme: alt
      text: Quickstart
      link: /api-examples
    - theme: alt
      text: Github
      link: https://github.com/hengyoush/kyanos

features:
      - icon: 🌐️
        title: Lightweight and Compatible
        details: Kyanos, a network troubleshooting tool, operates without any external dependencies and is compatible with kernel versions from 3.10 to the latest
      - icon: 🚀
        title: Rapid Analysis
        details: With just one command, users can quickly inspect the machine's network issues, including the network latency and data transfer sizes of common services like MySQL and Redis.
      - icon: 🎯️
        title: Advanced Data Filtering
        details: Supports filtering data based on protocol fields (such as HTTP Path or Redis Command), process PID, container ID, and K8s Pod names.
      - icon: 💻️
        title: Container Network Monitoring
        details: In containerized environments, it can measure the latency of packets from the container's network interface to the host's.
      - icon: 📊️
        title: Intuitive TUI
        details: Command-line based, offering visual output without the need for complex file downloads and analysis steps like tcpdump.
      - icon: 📈️
        title: Powerful Aggregation Analysis
        details: Supports automatic data aggregation based on dimensions such as remote IP, protocol, etc., to quickly obtain specific information, such as the latency of certain HTTP paths from specific IPs, without the slow analysis of tcpdump.
---

