#!/bin/bash
BASEDIR=$(dirname "${0}")
cd ${BASEDIR}/../
BASEDIR=$(pwd)
cd ${BASEDIR}

BTFHUB_REPO="https://github.com/aquasecurity/btfhub.git"
BTFHUB_ARCH_REPO="https://github.com/aquasecurity/btfhub-archive.git"


KYANOS_BPF_CORE="${BASEDIR}/bpf/agent_$2_bpfel.o"
KYANOS_BPF_CORE_FOR_LEGACY_KERNEL="${BASEDIR}/bpf/agentlagacykernel310_$2_bpfel.o"
KYANOS_BPF_CORE_GOTLS="${BASEDIR}/bpf/gotls_$2_bpfel.o"

BTFHUB_DIR="${BASEDIR}/deps/btfhub"
BTFHUB_ARCH_DIR="${BASEDIR}/deps/btfhub-archive"

ARCH=$(uname -m)

case ${ARCH} in
"x86_64")
    ARCH="x86_64"
    ;;
"aarch64")
    ARCH="arm64"
    ;;
*)
    die "unsupported architecture"
    ;;
esac


die() {
    echo ${@}
    exit 1
}

branch_clean() {
    cd ${1} || die "could not change dirs"

    # small sanity check
    [ ! -d ./.git ] && die "$(basename $(pwd)) not a repo dir"

    # git fetch -a || die "could not fetch ${1}" # make sure its updated
    # git clean -fdX                             # clean leftovers
    # git reset --hard                           # reset letfovers
    # git checkout origin/main -b main-$$
    # git branch -D main
    # git branch -m main-$$ main # origin/main == main

    cd ${BASEDIR}
}

CMDS="rsync git cp rm mv"
for cmd in ${CMDS}; do
    command -v $cmd 2>&1 >/dev/null || die "cmd ${cmd} not found"
done
[ ! -f ${KYANOS_BPF_CORE} ] && die "kyanos CO-RE obj not found: ${KYANOS_BPF_CORE}"

[ ! -d ${BTFHUB_DIR} ] && git clone "${BTFHUB_REPO}" ${BTFHUB_DIR}
[ ! -d ${BTFHUB_ARCH_DIR} ] && git clone --depth=1 "${BTFHUB_ARCH_REPO}" ${BTFHUB_ARCH_DIR}

if [ -z ${SKIP_FETCH} ]; then
    branch_clean ${BTFHUB_DIR}
    branch_clean ${BTFHUB_ARCH_DIR}
fi

cd ${BTFHUB_DIR}


# sync only supported kernels

ARCH_EXCLUDE=$(printf "x86_64\naarch64\n" | grep -v $(uname -m) | xargs)
rsync -avz \
    ${BTFHUB_ARCH_DIR}/ \
    --exclude=.git* \
    --exclude=README.md \
    --exclude=${ARCH_EXCLUDE} \
    --include='*ubuntu*' \
    --include='*centos*' \
    --include='*debian*' \
    ./archive/

# generate tailored BTFs

[ ! -d ${BASEDIR}/bpf/custom-archive ] && mkdir -p ${BASEDIR}/bpf/custom-archive
rm -rf ${BASEDIR}/bpf/custom-archive/* || true

[ ! -f ./tools/btfgen.sh ] && die "could not find btfgen.sh"
./tools/btfgen.sh -a $1 -o ${KYANOS_BPF_CORE} -o ${KYANOS_BPF_CORE_FOR_LEGACY_KERNEL} -o ${KYANOS_BPF_CORE_GOTLS}

# move tailored BTFs to dist
mv ./custom-archive/* ${BASEDIR}/bpf/custom-archive
