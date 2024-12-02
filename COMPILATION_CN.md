# 编译步骤

本文介绍 kyanos 的本地编译方法，我的环境是ubuntu 22.04，其他环境可能会有所不同。

## 工具版本要求

- golang 1.23 以上
- clang 10.0 以上
- llvm 10.0 以上

## 编译环境依赖安装
### Ubuntu
如果你使用的是ubuntu 22.04以及更新版本，可以使用一条命令即可完成编译环境的初始化。
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/hengyoush/kyanos/master/init_env.sh)"
```
### 其他 Linux 发行版
编译环境除了上面工具链版本列出的软件外，还需要以下软件，请自行安装。

- linux-tools-common
- linux-tools-generic
- pkgconf
- libelf-dev

### 如果你的内核没开启BTF
如果没有开启BTF，那么虽然可能成功编译，但你可能无法成功启动 kyanos. 

检查是否开启BTF：
```
grep CONFIG_DEBUG_INFO_BTF "/boot/config-$(uname -r)"
```
如果结果是`CONFIG_DEBUG_INFO_BTF=y`说明开启了，如果没开启请到  [mirrors.openanolis.cn](https://mirrors.openanolis.cn/coolbpf/btf/) or [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/)上下载，然后启动 kyanos 时使用 `--btf` 选项指定下载的 btf 文件。


## 编译命令
执行
```
make build-bpf && make
```

之后在项目根目录下会生成 kyanos 可执行文件。
