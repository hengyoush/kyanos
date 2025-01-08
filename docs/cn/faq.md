---
next: false
prev: false
---

# FAQ

## 支持运行在 Windows / Mac 上吗 ？

目前还未支持，但后续有计划支持。([ISSUE-151](https://github.com/hengyoush/kyanos/issues/151))

## 支持运行在低版本内核上吗 ？

目前支持最低内核版本: 3.10.0-957，而且低版本内核下 kyanos 的会缺少某些功能。

目前 3.\*版本内核不支持根据容器 id/容器名称等过滤流量，也无法自动关联 NAT 前后的流量。

## 支持运行在 WSL 上的 Linux 吗 ?

理论上支持，但一般在 WSL 上的 Linux 发行版默认不带 linux
headers，但 kyanos 会依赖，所以可能需要修改编译选项手动编译内核，具体方法可参考：[Enabling eBPF/XDP for Kernel Tinkering on WSL2](https://dev.to/wiresurfer/unleash-the-forbidden-enabling-ebpfxdp-for-kernel-tinkering-on-wsl2-43fj)

## 可以运行在容器/Pod 里吗 ?

必须运行在具有特权模式下的容器/Pod 里。

## 当使用 `--pod-name` 选项时出现 "can not find any running pod by name xxx" 日志

Kyanos 必须与目标 Pod 运行在同一主机上。

## 运行出现 `can't find btf file to load!` 日志

可能是因为你的系统缺少了 btf 文件导致的，可以在这里
https://mirrors.openanolis.cn/coolbpf/btf/ 以及
https://github.com/aquasecurity/btfhub-archive/
这里手动下载和你的内核匹配的 BTF 文件，启动 kyanos 时通过 `--btf`
选项指定你下载的 btf 文件即可。

## 怎么理解 watch 结果中内核耗时的可视化部分 ?

![kyanos time detail](/faq-time-detail.png)  
每一个方块代表数据包经过的节点，从上面依次看起，第一个是 Process，代表请求从进程发出，到右边第二个节点 eth0@if483，这是容器内部的网卡设备，后边有一个(used: 0.02ms)代表从上一个节点 process 到容器内部网卡花费了 0.02ms。

以此类推，再到右边的 eth0 即为宿主机网卡，并且可以知道从容器网卡到虚拟机网卡花费了 0.02ms。

然后请求从网卡发出，到网卡接收到响应（即为图中所示的向下箭头），花费了 13.37ms，之后就是响应接收的流程，从右往左。

接着容器接收响应花费 0.06ms，再到响应数据复制到 TCP 缓存区花费了 0.06ms，最后进程从缓冲区读取数据花费了 0.11ms。

可以清楚的看到请求从进程发送到网卡，响应再从网卡复制到 Socket 缓冲区并且被进程读取的流程和每一个步骤的耗时。

## 运行 kyanos 后没有观察到 http 流量?

确认你想监控的协议不是 HTTP2，因为 kyanos 目前尚未支持。

## 运行后终端表格颜色不正确（比如无法选择表格中的记录）

![kyanos missing color](/missing-color.png)

检查是否有
`Your terminal does not support 256 colors, ui may display incorrectly`
日志，如果有说明终端的颜色配置不正确，kyanos 需要 256 色的终端。  
使用以下命令即可列出系统所支持的所有终端类型，以及他们支持的颜色位数：

```shell
for T in `find /usr/share/terminfo -type f -printf '%f '`;do echo "$T `tput -T $T colors`";done|sort -nk2|tail -n20
```

示例输出如下：

```shell
Eterm-88color 88
rxvt-88color 88
xterm-88color 88
xterm+88color 88
Eterm-256color 256
gnome-256color 256
iTerm.app 256
konsole-256color 256
...
```

$TERM变量代表当前终端类型，可使用echo $ TERM 命令查看。

可通过修改~/.bashrc 文件将其改为 256 色，在.bashrc 文件中加入以下代码即可：

```shell
case "$TERM" in
    xterm)
        export TERM=xterm-256color
        ;;
    screen)
        export TERM=screen-256color
        ;;
esac
```
