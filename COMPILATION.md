# Compilation Steps

This document describes the local compilation method for kyanos. My environment
is Ubuntu 22.04, and other environments may vary.

## Tool Version Requirements

- golang 1.23 or above
- clang 10.0 or above
- llvm 10.0 or above

## Installation of Compilation Environment Dependencies

### Ubuntu

If you are using Ubuntu 20.04 or later, you can initialize the compilation
environment with a single command.

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/hengyoush/kyanos/refs/heads/main/init_env.sh)"
```

### Other Linux Distributions

clone the project (don't forget to update submodle!):

```bash
git clone https://github.com/hengyoush/kyanos
cd kyanos
git submodule update --init --recursive
```

In addition to the toolchain versions listed above, the compilation environment
also requires the following software. Please install them manually.

- linux-tools-common
- linux-tools-generic
- pkgconf
- libelf-dev

## Compilation Commands

If you are just developing and testing locally, you can execute

```
make build-bpf && make
```

the kyanos executable file will be generated in the root directory of the
project.

> [!IMPORTANT]
>
> Note that this binary file does not include the BTF files from
> [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/). If you run
> this kyanos on a lower version kernel without BTF support, it may fail to
> start. You can build a kyanos artifact with embedded BTF files using the
> following commands:  
> x86_64:
>
> ```bash [x86_64]
> make build-bpf && make btfgen BUILD_ARCH=x86_64 ARCH_BPF_NAME=x86 && make
> ```
>
> arm64:
>
> ```bash [arm64]
> make build-bpf && make btfgen BUILD_ARCH=arm64 ARCH_BPF_NAME=arm64 && make
> ```
>
> Note that make btfgen may take more than 15 minutes.

> [!TIP]
>
> If your kernel does not have BTF enabled, you may not be able to start kyanos
> successfully.
>
> Check if BTF is enabled:
>
> ```
> zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz
> ```
>
> If the result is `CONFIG_DEBUG_INFO_BTF=y`, it means BTF is enabled. If not,
> please download the BTF file corresponding to your kernel version from
> [mirrors.openanolis.cn](https://mirrors.openanolis.cn/coolbpf/btf/) or
> [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/), and use the
> `--btf` option to specify the downloaded BTF file when starting kyanos.
