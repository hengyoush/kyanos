---
prev:
  text: 'Kyanos 是什么'
  link: './what-is-kyanos'
next: false
---


# 快速开始
## 安装要求

**内核版本要求**
- 3.x: 3.10.0-957 版本及以上内核
- 4.x: 4.14版本以上内核
- 5.x, 6.x: 全部支持

**处理器架构支持**
- amd64
- arm64

## 安装并运行 {#prerequire}

你可以从 [release page](https://github.com/hengyoush/kyanos/releases) 中下载以静态链接方式编译的适用于 x86_64 和 arm64 架构的二进制文件：

```bash
tar xvf kyanos_vx.x.x_linux_x86.tar.gz
```

然后输入
```bash
kyanos watch 
```

 如果显示了下面的表格：
![kyanos quick start success](/quickstart-success.png)
🎉 恭喜你，kyanos启动成功了。

> [!TIP]
> 如果上面的命令执行失败了？没关系，在这个 [FAQ](./faq) 里看看有没有符合你的情况，如果没有欢迎提出 [github issue](https://github.com/hengyoush/kyanos/issues) ! 

## 常见问题
### kyanos watch 执行后没有任何输出

检查启动kyanos时是否有这样的日志：

```js
find btf file exactly failed, try to find a lower version btf file...
```
如果有，可能是因为你的系统缺少了btf文件导致的，可以在这里 https://mirrors.openanolis.cn/coolbpf/btf/ 以及 https://github.com/aquasecurity/btfhub-archive/ 这里手动下载和你的内核匹配的BTF文件，启动kyanos时通过`--btf`选项指定你下载的btf文件即可。


## 下一步
- 快速了解 kyanos 的使用方法，请查看：[5分钟学会使用kyanos](./how-to)


