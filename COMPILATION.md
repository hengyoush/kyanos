# Compilation Steps

This document describes the local compilation method for kyanos. My environment is Ubuntu 22.04, and other environments may vary.

## Tool Version Requirements

- golang 1.23 or above
- clang 10.0 or above
- llvm 10.0 or above

## Installation of Compilation Environment Dependencies
### Ubuntu
If you are using Ubuntu 22.04 or later, you can initialize the compilation environment with a single command.
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/hengyoush/kyanos/master/init_env.sh)"
```
### Other Linux Distributions
In addition to the toolchain versions listed above, the compilation environment also requires the following software. Please install them manually.

- linux-tools-common
- linux-tools-generic
- pkgconf
- libelf-dev

### If Your Kernel Does Not Enable BTF
If BTF is not enabled, you may be able to compile successfully, but you may not be able to start kyanos successfully.

Check if BTF is enabled:
```
grep CONFIG_DEBUG_INFO_BTF "/boot/config-$(uname -r)"
```
If the result is `CONFIG_DEBUG_INFO_BTF=y`, it means BTF is enabled. If not, please download from [mirrors.openanolis.cn](https://mirrors.openanolis.cn/coolbpf/btf/) or [btfhub-archive](https://github.com/aquasecurity/btfhub-archive/), and use the `--btf` option to specify the downloaded BTF file when starting kyanos.

## Compilation Command
Execute
```
make build-bpf && make
```

Afterwards, the kyanos executable will be generated in the root directory of the project.