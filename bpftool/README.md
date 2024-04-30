<a href=".github/assets/">
  <div>
    <img src=".github/assets/bpftool_horizontal_color.svg"
         alt="bpftool logo: Hannah the Honeyguide"
         width=500px; />
  </div>
</a>

[![License BSD 2-Clause][bsd-badge]](LICENSE.BSD-2-Clause)
[![License GPL 2.0][gpl-badge]](LICENSE.GPL-2.0)
[![Build status][build-badge]][build]

[bsd-badge]: https://img.shields.io/badge/License-BSD_2--Clause-blue.svg
[gpl-badge]: https://img.shields.io/badge/License-GPL_2.0-blue.svg
[build-badge]: https://github.com/libbpf/bpftool/actions/workflows/build.yaml/badge.svg
[build]: https://github.com/libbpf/bpftool/actions/workflows/build.yaml

This is the official home for bpftool. _Please use this Github repository for
building and packaging bpftool and when using it in your projects through Git
submodule._

The _authoritative source code_ of bpftool is developed as part of the
[bpf-next Linux source tree][bpf-next] under [the `tools/bpf/bpftool`
subdirectory][tools-bpf-bpftool] and is periodically synced to
<https://github.com/libbpf/bpftool> on Github. As such, all changes for bpftool
**should be sent to the [BPF mailing list][bpf-ml]**, **please don't open PRs
here** unless you are changing some Github-specific components.

[bpf-next]: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git
[tools-bpf-bpftool]: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/bpf/bpftool
[bpf-ml]: http://vger.kernel.org/vger-lists.html#bpf

Questions on bpftool and BPF general usage
------------------------------------------

Check out [the manual pages](docs) for documentation about bpftool. A number of
example invocations are also displayed in [this blog
post](https://qmonnet.github.io/whirl-offload/2021/09/23/bpftool-features-thread/).

All general BPF questions, including kernel functionality, bpftool features and
usage, should be sent to bpf@vger.kernel.org mailing list. You can subscribe to
it [here][bpf-ml] and search its archives [here][lore].

The mailing list is monitored by many more people than this repo and they will
happily try to help you with whatever issue you encounter. This repository's
PRs and issues should be opened only for dealing with issues related to
components specific to the bpftool mirror repository (such as the
synchronization script or the CI workflows). The project maintainers also use
GitHub issues as a generic tracker for bpftool, but issues should first be
reported on the mailing list nonetheless.

[lore]: https://lore.kernel.org/bpf/

Dependencies
------------

Required:

- libelf
- zlib

Optional:

- libbfd (for dumping JIT-compiled program instructions)
- libcap (for better feature probing)
- kernel BTF information (for profiling programs or showing PIDs of processes
  referencing BPF objects)
- clang/LLVM (idem)

Build
-----

### Initialize libbpf submodule

This repository uses libbpf as a submodule. You can initialize it when cloning
bpftool:

```console
$ git clone --recurse-submodules https://github.com/libbpf/bpftool.git
```

Alternatively, if you have already cloned the repository, you can initialize
the submodule by running the following command from within the repository:

```console
$ git submodule update --init
```

### Build bpftool

To build bpftool:

```console
$ cd src
$ make
```

To build and install bpftool on the system:

```console
$ cd src
# make install
```

Building bpftool in a separate directory is supported via the `OUTPUT` variable:

```console
$ mkdir /tmp/bpftool
$ cd src
$ OUTPUT=/tmp/bpftool make
```

Most of the output is suppressed by default, but detailed building logs can be
displayed by passing `V=1`:

```console
$ cd src
$ make V=1
```

Additional compilation flags can be passed to the command line if required. For
example, we can create a static build with the following commands:

```console
$ cd src
$ EXTRA_CFLAGS=--static make
```

Note that to use the LLVM disassembler with static builds, we need a static
version of the LLVM library installed on the system:

1.  Download a precompiled LLVM release or build it locally.

    - Download the appropriate
      [release of LLVM](https://releases.llvm.org/download.html) for your
      platform, for example on x86_64 with LLVM 15.0.0:

      ```console
      $ curl -LO https://github.com/llvm/llvm-project/releases/download/llvmorg-15.0.0/clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz
      $ tar xvf clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4.tar.xz
      $ mv clang+llvm-15.0.0-x86_64-linux-gnu-rhel-8.4 llvm_build
      ```

    - Alternatively, clone and build the LLVM libraries locally.

      ```console
      $ git clone https://github.com/llvm/llvm-project.git
      $ mkdir llvm_build
      $ cmake -S llvm-project/llvm -B llvm_build -DCMAKE_BUILD_TYPE=Release
      $ make -j -C llvm_build llvm-config llvm-libraries
      ```

2.  Build bpftool with `EXTRA_CFLAGS` set to `--static`, and by passing the
    path to the relevant `llvm-config`.

    ```console
    $ cd bpftool
    $ LLVM_CONFIG=../../llvm_build/bin/llvm-config EXTRA_CFLAGS=--static make -j -C src
    ```

### Build bpftool's man pages

The man pages for bpftool can be built with:

```console
$ cd docs
$ make
```

They can be installed on the system with:

```console
$ cd docs
# make install
```

bpf-next to GitHub sync
-----------------------

This repository mirrors [bpf-next Linux source tree's
`tools/bpf/bpftool`][tools-bpf-bpftool] directory, plus its few dependencies
from under `kernel/bpf/`, and its supporting header files. Some of these header
files, `include/linux/*.h` on the current repository, are reduced versions of
their counterpart files at [bpf-next][bpf-next]'s `tools/include/linux/*.h` to
make compilation successful.

Synchronization between the two repositories happens every few weeks or so.
Given that bpftool remains aligned on libbpf's version, its repository tends to
follow libbpf's. When the libbpf repo syncs up with bpf-next, bpftool's repo
usually follows within the next few days.

The synchronization process is semi-automated: the script in
`scripts/sync-kernel.sh` cherry-picks, adjusts and commits all changes from
`bpf-next` to a local version of the bpftool repository. However, maintainers
run this script manually and then create a pull request to merge the resulting
commits.

Take a look at [the script](scripts/sync-kernel.sh) for the technical details of the process. See also the documentation in [the accompanying README.md](scripts#sync-kernelsh)

License
-------

This work is dual-licensed under the GNU GPL v2.0 (only) license and the BSD
2-clause license. You can select either of them if you reuse this work.

`SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)`
