#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# Use this script to add labels to GitHub release assets for a given release.
#
# Based on the following console workflow:
#
# gh api \
#     '/repos/qmonnet/bpftool/releases/tags/v7.2.0-snapshot.0' \
#     --jq '.id'
# gh api \
#     '/repos/qmonnet/bpftool/releases/96330927/assets' \
#     --jq '.[] | select(.name == "bpftool-amd64.tar.gz").id'
# gh api \
#     --method PATCH \
#     -H "Accept: application/vnd.github+json" \
#     -H "X-GitHub-Api-Version: 2022-11-28" \
#     '/repos/qmonnet/bpftool/releases/assets/100280866' \
#     -f name='bpftool-arm64.tar.gz' \
#     -f label='Compressed binary (arm64)'

REPO="libbpf/bpftool"

usage() {
    echo "Update asset labels for bpftool releases"
    echo "Usage:"
    echo "  $0 [options] <release_tag>"
    echo ""
    echo "OPTIONS"
    echo " -h       display this help"
    exit "$1"
}

OPTIND=1
while getopts "h" opt; do
    case "$opt" in
    h)
        usage 0
        ;;
    *)
        usage 1
        ;;
    esac
done
shift $((OPTIND-1))
[[ "${1:-}" = "--" ]] && shift

# Get release tag from command line
if [[ "$#" -lt 1 ]]; then
    echo "error: missing release tag"
    usage 1
fi
release_tag="$1"
echo "repo: ${REPO}, release tag: ${release_tag}"

# Add labels to set for given asset names here:
declare -A assets_labels=(
    ["bpftool-libbpf-${release_tag}-sources.tar.gz"]="Source code, including libbpf submodule (tar.gz)"
)

# Get release ID
release_id="$(gh api "/repos/${REPO}/releases/tags/${release_tag}" --jq '.id')"
echo "  found release ID ${release_id}"

# For each label to set, get asset ID, prompt user for confirmation, set label
for asset_name in "${!assets_labels[@]}"; do
    asset_id="$(gh api "/repos/${REPO}/releases/${release_id}/assets" \
        --jq ".[] | select(.name == \"${asset_name}\").id")"
    echo "  found asset ID ${asset_id}"

    echo "asset '${asset_name}': add label '${assets_labels[${asset_name}]}'"
    answer=""
    read -rp 'proceed? [y/N]: ' answer

    case "${answer}" in
        y|yes|Y|Yes|YES)
            gh api \
                --method PATCH \
                -H 'Accept: application/vnd.github+json' \
                -H 'X-GitHub-Api-Version: 2022-11-28' \
                "/repos/${REPO}/releases/assets/${asset_id}" \
                -f label="${assets_labels[${asset_name}]}"
            ;;
        *)
            echo "cancelled"
            ;;
    esac
done
