---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "Kyanos"
  text: "A Simple & Powerful Network Tracing Tool"
  tagline: Visualize the time packets spend in the kernel, watch & analyze in command line.
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
        title: Easy-to-use
        details: Focusing on the Layer 7 protocol, capture and analyze application layer network performance with a single command.
        link: ./how-to
        linkText: Learn how to use kyanos
      - icon: 🎯️
        title: Advanced Traffic Filtering
        details: Supports filtering traffic based on protocol fields (such as HTTP Path or Redis Command), process PID, container ID, and K8s Pod names.
        link: ./watch#how-to-filter
        linkText: Learn how to filter traffic
      - icon: 📈️
        title: Powerful Aggregation Analysis
        details: Supports automatic traffic aggregation based on various dimensions such as remote IP, protocol, etc., to quickly obtain specific information, such as the latency of certain HTTP paths from specific IPs.
        link: ./stat
        linkText: Learn how to analysis traffic
      - icon: 💻️
        title: Container Network Monitoring
        details: In containerized environments, it can measure the latency of packets from the container's network interface to the host's.
        link: ./watch#filter-by-container
        linkText: Capture container traffic
      - icon: 📊️
        title: Intuitive TUI
        details: Command-line based, offering visual output without the need for complex file downloads and analysis steps like tcpdump.
        link: ./how-to
        linkText: Learn how to use kyanos
      - icon: 🌐️
        title: Lightweight and Compatible
        details: Operates without any external dependencies and is compatible with kernel versions from 3.10 to the latest
        link: ./quickstart#prerequire
        linkText: Install kyanos
---

