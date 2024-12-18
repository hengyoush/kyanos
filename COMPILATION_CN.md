# 编译步骤

本文介绍 kyanos 的本地编译方法，我的环境是ubuntu 22.04，其他环境可能会有所不同。

## 工具版本要求

- golang 1.23 以上
- clang 10.0 以上
- llvm 10.0 以上

## 编译环境依赖安装
### Ubuntu
如果你使用的是ubuntu 20.04以及更新版本，可以使用一条命令即可完成编译环境的初始化。
```
/bin/bash -c "$(curl -fsSL https://github.com/hengyoush/kyanos/blob/main/init_env.sh)"
```
### 其他 Linux 发行版
用下面的命令 clone 项目:
```bash
git clone https://github.com/hengyoush/kyanos
cd kyanos
git submodule update --init --recursive
```

编译环境除了上面工具链版本列出的软件外，还需要以下软件，请自行安装。

- linux-tools-common
- linux-tools-generic
- pkgconf
- libelf-dev

## 编译命令

如果只是本地开发测试，可以执行
```
make build-bpf && make
```

之后在项目根目录下会生成 kyanos 可执行文件。

> [!IMPORTANT]
> 但是需要注意的是该二进制文件中没有包含 [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/) 中的 btf 文件，如果直接拿这个 kyanos 去没有开启 BTF 支持的低版本内核上执行可能会启动失败，通过下面的命令可以构建出一个内嵌 btf 文件的 kyanos 产物：  
> x86_64:  
>```bash [x86_64]
>make build-bpf && make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86 && make
>```  
>arm64: 
>```bash [arm64]
>make build-bpf && make btfgen BUILD_ARCH=arm64 ARCH_BPF_NAME=arm64 && make
>```
>
> 需要注意 `make btfgen` 耗时可能超过 15min。


> [!TIP]
>如果你的内核没有开启BTF，你可能无法成功启动 kyanos. 
>
>检查是否开启BTF：
>```
>grep CONFIG_DEBUG_INFO_BTF "/boot/config-$(uname -r)"
>```
>如果结果是`CONFIG_DEBUG_INFO_BTF=y`说明开启了，如果没开启请到  [mirrors.openanolis.cn](https://mirrors.openanolis.cn/coolbpf/btf/) or [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/)上下载对应你的内核版本的 btf 文件，然后启动 kyanos 时使用 `--btf` 选项指定下载的 btf 文件。


