#!/usr/bin/env bash
set -e

PROJECT_ROOT_DIR=$(pwd)
OPENSSL_DIR="${PROJECT_ROOT_DIR}/deps/openssl"
OUTPUT_DIR="${PROJECT_ROOT_DIR}/bpf"

if [[ ! -f "go.mod" ]]; then
  echo "Run the script from the project root directory"
  exit 1
fi

echo "check file exists: ${OPENSSL_DIR}/.git"
# skip cloning if the header file of the max supported version is already generated
if [[ ! -f "${OPENSSL_DIR}/.git" ]]; then
  echo "check directory exists: ${OPENSSL_DIR}"
  # skip cloning if the openssl directory already exists
  if [[ ! -d "${OPENSSL_DIR}" ]]; then
    echo "git clone openssl to ${OPENSSL_DIR}"
    git clone https://wget.la/github.com/openssl/openssl.git ${OPENSSL_DIR}
  fi
fi

function run() {
  git fetch --tags
  cp -f ${PROJECT_ROOT_DIR}/utils/openssl_3_5_0_offset.c ${OPENSSL_DIR}/offset.c
  declare -A sslVerMap=()
  sslVerMap["0"]="0"
  # sslVerMap["1"]="0"
  # sslVerMap["2"]="0"

  # shellcheck disable=SC2068
  for ver in ${!sslVerMap[@]}; do
    tag="openssl-3.5.${ver}"
    val=${sslVerMap[$ver]}
    header_file="${OUTPUT_DIR}/openssl_3_5_${val}.bpf.c"
    header_define="OPENSSL_3_5_$(echo ${val} | tr "[:lower:]" "[:upper:]")_KERN_H"

    if [[ -f ${header_file} ]]; then
      echo "Skip ${header_file}"
      continue
    fi
    echo "git checkout ${tag}"
    git checkout ${tag}
    echo "Generating ${header_file}"


    # ./Configure and make openssl/opensslconf.h
    ./Configure
    make clean
    make build_generated


    clang -I include/ -I . offset.c -o offset

    # //go:build ignore
    echo -e "//go:build ignore\n" >${header_file}
    echo -e "#ifndef ECAPTURE_${header_define}" >>${header_file}
    echo -e "#define ECAPTURE_${header_define}\n" >>${header_file}
    ./offset >>${header_file}
    echo -e "#define SSL_ST_VERSION SSL_CONNECTION_ST_VERSION\n" >>${header_file}
    echo -e "#define SSL_ST_WBIO SSL_CONNECTION_ST_WBIO\n" >>${header_file}
    echo -e "#define SSL_ST_RBIO SSL_CONNECTION_ST_RBIO\n" >>${header_file}
    echo -e "\n#include \"openssl.h\"" >>${header_file}
    # echo -e "#include \"openssl_masterkey_3.3.h\"" >>${header_file}
    echo -e "\n#endif" >>${header_file}

    # clean up
    make clean

  done

  rm offset.c
}

# TODO Check if the directory for OpenSSL exists
pushd ${OPENSSL_DIR}
(run)
[[ "$?" != 0 ]] && popd
popd
