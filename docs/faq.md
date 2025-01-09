---
next: false
prev: false
---

# FAQ

## Does it support running on Windows / Mac?

Not yet, but there are plans to support it in the
future.([ISSUE-151](https://github.com/hengyoush/kyanos/issues/151))

## Does it support running on lower kernel versions?

Currently, it supports the minimum kernel version: 3.10.0-957, but some features
may be missing on lower kernel versions.

Currently, 3.\* kernel versions do not support filtering traffic by container
ID/container name and cannot automatically associate traffic before and after
NAT.

## Does it support running on Linux in WSL?

Theoretically yes, but Linux distributions on WSL usually do not include Linux
headers by default, which kyanos depends on. You may need to modify the
compilation options to manually compile the kernel. For specific methods, refer
to:
[Enabling eBPF/XDP for Kernel Tinkering on WSL2](https://dev.to/wiresurfer/unleash-the-forbidden-enabling-ebpfxdp-for-kernel-tinkering-on-wsl2-43fj)

## Can it run in a container/Pod?

It must run in a privileged mode container/Pod.

## When using the --pod-name option, the "can not find any running pod by name xxx" log appears

Kyanos must be running on the same host as the target Pod.

## `can't find btf file to load!` log appears during operation

This may be because your system lacks the BTF file. You can manually download
the BTF file that matches your kernel from here:
https://mirrors.openanolis.cn/coolbpf/btf/ and
https://github.com/aquasecurity/btfhub-archive/. Specify the downloaded BTF file
with the `--btf` option when starting kyanos.

## How to understand the visualization of kernel time in the watch results?

![kyanos time detail](/faq-time-detail.png)  
Each block represents a node that the packet passes through. Starting from the
top, the first is Process, representing the request sent from the process to the
second node on the right, eth0@if483, which is the internal network card device
of the container. The following (used:0.02ms) indicates that it took 0.02ms from
the previous node process to the internal network card of the container.

By analogy, the next node on the right is eth0, which is the host network card,
and it can be seen that it took 0.02ms from the container network card to the
virtual machine network card.

Then the request is sent from the network card, and it takes 13.37ms to receive
the response from the network card (as shown by the downward arrow in the
figure). After that, the response receiving process starts from right to left.

Then the container receives the response, which takes 0.06ms, and then it takes
0.06ms to copy the response data to the TCP buffer. Finally, it takes 0.11ms for
the process to read the data from the buffer.

You can clearly see the process and time consumption of the request from the
process sending to the network card, and the response from the network card
copying to the Socket buffer and being read by the process.

## No HTTP traffic observed after running kyanos?

Make sure the protocol you want to monitor is not HTTP2, as kyanos does not
currently support it.

## Incorrect terminal table colors after running (e.g., unable to select records in the table)

![kyanos missing color](/missing-color.png)

Check if there is a
`Your terminal does not support 256 colors, ui may display incorrectly` log. If
so, it means the terminal color configuration is incorrect. Kyanos requires a
256-color terminal.  
Use the following command to list all terminal types supported by the system and
their supported color bits:

```shell
for T in `find /usr/share/terminfo -type f -printf '%f '`;do echo "$T `tput -T $T colors`";done|sort -nk2|tail -n20
```

Example output:

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

The $TERM variable represents the current terminal type, which can be viewed
using the echo $TERM command.

You can change it to 256 colors by modifying the ~/.bashrc file. Add the
following code to the .bashrc file:

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
