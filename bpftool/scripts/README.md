# Scripts

This directory contains scripts for maintaining bpftool's GitHub mirror.

## gh-label-release-assets.sh

This script can **add labels to GitHub release assets**. Labels are used in the
GitHub interface instead of the file name in the list of assets, but they do
not alter the download URL.

The script takes the tag reference for the release as single parameter. The
repository to use, and the names and labels to set for assets are currently
defined in the script itself.

It requires the [GitHub command line][gh] (`gh`).

Note that only users with push access to the repository can update release
assets and set labels.

[gh]: https://cli.github.com/

## sync-kernel.sh

### Synchronize Linux and bpftool mirror

This script synchronizes the bpftool mirror with the bpftool sources (and
related files) from the Linux kernel repository.

Synchronization is usually performed against the `bpf-next` and `bpf` trees,
because this is where most bpftool updates are merged.

By default, the script does not pick the very latest commits in these trees,
but instead it uses the commits referenced in the libbpf submodule. This is
because bpftool strongly relies on libbpf, and the libbpf GitHub mirror is used
here as a submodule dependency. This libbpf mirror is also periodically updated
to the latest `bpf-next` and `bpf` tree, and records to what kernel commits it
was brought up-to-date. To ensure optimal compatibility between the bpftool
sources and the libbpf dependency, we want to update them to the same point of
reference.

### Prerequisites

There is no particular tool required for running the script, except `git` of
course.

However, you need a local copy of the Linux Git repository on your system
in order to successfully run the script. You can set it up as follows:

```console
$ git clone 'https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git' linux
$ cd linux
$ git remote rename origin bpf-next
$ git branch --move master bpf-next
$ git remote add bpf 'https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf.git'
$ git fetch bpf
$ git checkout bpf/master
$ git switch --create bpf
$ git branch --set-upstream-to bpf/master
$ git switch bpf-next
```

At the end of the process, the repository should contain two branches
`bpf-next` and `bpf`, pointing to the `master` branches of the `bpf-next` and
`bpf` remote repositories, respectively. These two branches are required to
synchronize the mirror correctly.

You can later update this repository with the following commands:

```console
$ git switch bpf
$ git pull --set-upstream bpf master
$ git switch bpf-next
$ git pull --set-upstream bpf-next master
```

Also make sure you have cloned the bpftool mirror recursively, to check out the
libbpf submodule. If you have not, run the following:

```console
$ git submodule update --init
```

### Usage

As preliminary steps:

- Make sure that you have a Linux Git repository installed (see above), with
  two branches `bpf-next` and `bpf` up-to-date.
- Make sure your mirror repository is clean.

Then run the script:

```console
$ ./sync-kernel.sh <bpftool-repo> <kernel-repo>
```

If working from within the bpftool repository, the path to the `<bpftool-repo>`
is typically the current working directory (`.`). The second argument,
`<kernel-repo>`, is the path to the Linux Git repository mentioned earlier.

Several environment variables can modify some internal parameters of the
script:

- Set `BPF_NEXT_BASELINE `to override the `bpf-next` tree commit to use (the
  commit from the `bpf-next` branch with which the bpftool repository is
  currently synchronized, prior to running the script). If unset, use the hash
  from `<bpftool-repo>/CHECKPOINT-COMMIT` is used.
- Set `BPF_BASELINE `to override the `bpf` tree commit to use (the commit from
  the `bpf` branch with which the bpftool repository is currently synchronized,
  prior to running the script). If unset, use the hash from
  `<bpftool-repo>/BPF-CHECKPOINT-COMMIT` is used.
- Set `BPF_NEXT_TIP_COMMIT` to override the `bpf-next` tree target commit (the
  commit in `bpf-next` up to which the bpftool mirror should be synchronized).
  If unset, use the hash from `<bpftool-repo>/libbpf/CHECKPOINT-COMMIT`, after
  the libbpf repository update that takes place at the beginning of the update
  process.
- Set `BPF_TIP_COMMIT` to override the `bpf` tree target commit (the commit in
  `bpf` up to which the bpftool mirror should be synchronized). If unset, use
  the hash from `<bpftool-repo>/libbpf/BPF-CHECKPOINT-COMMIT`, after the libbpf
  repository update that takes place at the beginning of the update process.
- Set `SKIP_LIBBPF_UPDATE` to `1` to avoid updating libbpf automatically.
- Set `MANUAL_MODE` to `1` to manually control every cherry-picked commit.

### How it works

This script synchronizes the bpftool mirror with upstream bpftool sources from
the Linux kernel repository.

It performs the following steps:

- First, the script updates the libbpf submodule, commits the change, and (by
  default) picks up libbpf's latest checkpoints to use them as target commits
  for the bpftool mirror.

- In the Linux repository, from the `bpf-next` branch, it creates new branches,
  filters out all non-bpftool-related files, and reworks the layout to
  replicate the layout from the bpftool mirror.

- It generates patches for each commit touching `bpftool` or the required UAPI
  files, up to the target commit, and exports these patches to a temporary
  repository.

- In a new branch in the bpftool mirror, the script applies (`git am`) each of
  these patches to the mirror.

- Then the script checks out the `bpf` branch in the Linux repository, and
  repeats the same operations.

- On top of the new patches applied to the mirror, the script creates a last
  commit with the updated checkpoints, using a cover letter summarizing the
  changes as the commit description.

- The next step is verification. The script applies to the Linux repository
  (`bpf-next` branch) a patch containing known differences between the Linux
  repository and the bpftool mirror. Then it looks for remaining differences
  between the two repositories, and warn the user if it finds any. Patches
  picked up from the `bpf` tree are usually a source of differences at this
  step. If the patch containing the known differences is to be updated after
  the synchronization in progress, the user should do it at this time, before
  the temporary files from the script are deleted.

- At last, the script cleans up the temporary files and branches in the Linux
  repository. Note that these temporary files and branches are not cleaned up
  if the script fails during execution.
