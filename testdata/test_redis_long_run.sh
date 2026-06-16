#!/usr/bin/env bash
. "$(dirname "$0")/common.sh"
set -euo pipefail

CMD="${1:-}"
DOCKER_REGISTRY="${2:-}"

if [ -z "$CMD" ]; then
    echo "usage: $0 '<kyanos command>' [docker_registry]" >&2
    exit 1
fi

REDIS_LONG_RUN_ROUNDS="${REDIS_LONG_RUN_ROUNDS:-8}"
REDIS_LONG_RUN_BATCH_SIZE="${REDIS_LONG_RUN_BATCH_SIZE:-2000}"
REDIS_LONG_RUN_GROWTH_LIMIT_MB="${REDIS_LONG_RUN_GROWTH_LIMIT_MB:-64}"
REDIS_LONG_RUN_PPROF_ADDR="${REDIS_LONG_RUN_PPROF_ADDR:-127.0.0.1:6060}"
REDIS_LONG_RUN_OUTPUT_DIR="${REDIS_LONG_RUN_OUTPUT_DIR:-/tmp/kyanos-redis-long-run}"
REDIS_LONG_RUN_USE_LOCAL_SERVER="${REDIS_LONG_RUN_USE_LOCAL_SERVER:-0}"

FILE_PREFIX="${REDIS_LONG_RUN_OUTPUT_DIR}/redis_long_run"
WATCH_LOG="${FILE_PREFIX}.watch.log"
REDIS_PIPE_LOG="${FILE_PREFIX}.redis.log"
HEAP_BASELINE="${FILE_PREFIX}.baseline.pb.gz"
HEAP_FINAL="${FILE_PREFIX}.final.pb.gz"
REDIS_PID_FILE="${FILE_PREFIX}.redis.pid"

mkdir -p "${REDIS_LONG_RUN_OUTPUT_DIR}"

if [ -z "$DOCKER_REGISTRY" ]; then
    IMAGE_NAME="redis:7.0.14"
else
    IMAGE_NAME="${DOCKER_REGISTRY}/library/redis:7.0.14"
fi

cname='test-redis-long-run'
KYANOS_PID=""
REDIS_SERVER_MODE=""

cleanup() {
    if [ -n "${KYANOS_PID}" ] && kill -0 "${KYANOS_PID}" >/dev/null 2>&1; then
        kill "${KYANOS_PID}" >/dev/null 2>&1 || true
        wait "${KYANOS_PID}" >/dev/null 2>&1 || true
    fi
    if [ "${REDIS_SERVER_MODE}" = "docker" ]; then
        docker rm -f "${cname}" >/dev/null 2>&1 || true
    elif [ "${REDIS_SERVER_MODE}" = "local" ] && [ -f "${REDIS_PID_FILE}" ]; then
        kill "$(cat "${REDIS_PID_FILE}")" >/dev/null 2>&1 || true
        rm -f "${REDIS_PID_FILE}"
    fi
}
trap cleanup EXIT

wait_for_pprof() {
    local attempts=0
    until curl -fsS "http://${REDIS_LONG_RUN_PPROF_ADDR}/debug/pprof/" >/dev/null; do
        attempts=$((attempts + 1))
        if [ "${attempts}" -ge 30 ]; then
            echo "pprof endpoint did not become ready" >&2
            exit 1
        fi
        sleep 1
    done
}

collect_heap_profile() {
    local target_file="$1"
    curl -fsS "http://${REDIS_LONG_RUN_PPROF_ADDR}/debug/pprof/heap?gc=1" -o "${target_file}"
}

profile_total_bytes() {
    local target_file="$1"
    PROFILE_PATH="${target_file}" python3 - <<'PY'
import os
import re
import subprocess
import sys

profile = os.environ["PROFILE_PATH"]
cmd = ["go", "tool", "pprof", "-sample_index=inuse_space", "-top", "-nodecount=1", profile]
output = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
match = re.search(r" of ([0-9.]+)([A-Za-z]+) total", output)
if not match:
    sys.stderr.write(output)
    raise SystemExit("failed to parse pprof total")

value = float(match.group(1))
unit = match.group(2)
unit_table = {
    "B": 1,
    "kB": 1000,
    "KB": 1000,
    "MB": 1000 ** 2,
    "GB": 1000 ** 3,
    "TB": 1000 ** 4,
}
if unit not in unit_table:
    raise SystemExit(f"unknown pprof unit: {unit}")
print(int(value * unit_table[unit]))
PY
}

generate_redis_traffic_round() {
    local round="$1"
    : > "${REDIS_PIPE_LOG}"
    for i in $(seq 1 "${REDIS_LONG_RUN_BATCH_SIZE}"); do
        local key="kyanos:longrun:${round}:${i}"
        printf 'SET %s value-%s-%s\n' "${key}" "${round}" "${i}"
        printf 'GET %s\n' "${key}"
        printf 'DEL %s\n' "${key}"
    done | redis-cli --pipe > "${REDIS_PIPE_LOG}"
}

start_redis_server() {
    if [ "${REDIS_LONG_RUN_USE_LOCAL_SERVER}" = "1" ]; then
        if ! command -v redis-server >/dev/null 2>&1; then
            echo "redis-server is required when REDIS_LONG_RUN_USE_LOCAL_SERVER=1" >&2
            exit 1
        fi
        redis-server --save "" --appendonly no --bind 127.0.0.1 --port 6379 --daemonize yes --pidfile "${REDIS_PID_FILE}"
        REDIS_SERVER_MODE="local"
        return
    fi

    if docker pull "${IMAGE_NAME}"; then
        docker rm -f "${cname}" >/dev/null 2>&1 || true
        docker run --name "${cname}" -p 6379:6379 -d "${IMAGE_NAME}" >/dev/null
        REDIS_SERVER_MODE="docker"
        return
    fi

    if command -v redis-server >/dev/null 2>&1; then
        echo "docker pull failed, falling back to local redis-server" >&2
        redis-server --save "" --appendonly no --bind 127.0.0.1 --port 6379 --daemonize yes --pidfile "${REDIS_PID_FILE}"
        REDIS_SERVER_MODE="local"
        return
    fi

    echo "failed to start redis server with docker and no local redis-server fallback is available" >&2
    exit 1
}

main() {
    start_redis_server

    ${CMD} watch --json-output stdout redis --remote-ports 6379 --pprof --pprof-addr "${REDIS_LONG_RUN_PPROF_ADDR}" \
        > "${WATCH_LOG}" 2>&1 &
    KYANOS_PID=$!

    wait_for_pprof
    sleep 5

    generate_redis_traffic_round "warmup"
    collect_heap_profile "${HEAP_BASELINE}"

    for round in $(seq 1 "${REDIS_LONG_RUN_ROUNDS}"); do
        generate_redis_traffic_round "${round}"
        sleep 1
    done

    collect_heap_profile "${HEAP_FINAL}"
    if [ ! -s "${HEAP_BASELINE}" ] || [ ! -s "${HEAP_FINAL}" ]; then
        echo "heap profiles were not captured correctly" >&2
        exit 1
    fi

    local baseline_bytes
    local final_bytes
    local growth_limit_bytes
    baseline_bytes="$(profile_total_bytes "${HEAP_BASELINE}")"
    final_bytes="$(profile_total_bytes "${HEAP_FINAL}")"
    growth_limit_bytes=$((REDIS_LONG_RUN_GROWTH_LIMIT_MB * 1024 * 1024))

    echo "baseline_bytes=${baseline_bytes}"
    echo "final_bytes=${final_bytes}"
    echo "growth_limit_bytes=${growth_limit_bytes}"

    if [ $((final_bytes - baseline_bytes)) -gt "${growth_limit_bytes}" ]; then
        echo "heap usage grew beyond threshold during redis long-run test" >&2
        exit 1
    fi
}

main
