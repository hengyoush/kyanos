#!/usr/bin/env bash

usage () {
	echo "USAGE: ./sync-kernel.sh <bpftool-repo> <kernel-repo>"
	echo ""
	echo "This script synchronizes the mirror with upstream bpftool sources from the kernel repository."
	echo "It performs the following steps:"
	echo "  - Update the libbpf submodule, commit, and use its new checkpoints as target commits for bpftool."
	echo "  - Cherry-pick commits from the bpf-next branch, up to the bpf-next target commit."
	echo "  - Cherry-pick commits from the bpf branch, up to the bpf target commit."
	echo "  - Create a new commit with the updated version and checkpoints."
	echo "  - Check consistency."
	echo ""
	echo "Set BPF_NEXT_BASELINE to override bpf-next tree commit, otherwise read from <bpftool-repo>/CHECKPOINT-COMMIT."
	echo "Set BPF_BASELINE to override bpf tree commit, otherwise read from <bpftool-repo>/BPF-CHECKPOINT-COMMIT."
	echo "Set BPF_NEXT_TIP_COMMIT to override bpf-next tree target commit, otherwise read from <bpftool-repo>/libbpf/CHECKPOINT-COMMIT, after libbpf update."
	echo "Set BPF_TIP_COMMIT to override bpf tree target commit, otherwise read from <bpftool-repo>/libbpf/BPF-CHECKPOINT-COMMIT, after libbpf update."
	echo "Set SKIP_LIBBPF_UPDATE to 1 to avoid updating libbpf automatically."
	echo "Set MANUAL_MODE to 1 to manually control every cherry-picked commit."
	exit 1
}

set -eu

BPFTOOL_REPO=${1-""}
LINUX_REPO=${2-""}

if [ -z "${BPFTOOL_REPO}" ] || [ -z "${LINUX_REPO}" ]; then
	echo "Error: bpftool or linux repos are not specified"
	usage
fi

BASELINE_COMMIT=${BPF_NEXT_BASELINE:-$(cat "${BPFTOOL_REPO}"/CHECKPOINT-COMMIT)}
BPF_BASELINE_COMMIT=${BPF_BASELINE:-$(cat "${BPFTOOL_REPO}"/BPF-CHECKPOINT-COMMIT)}

if [ -z "${BASELINE_COMMIT}" ] || [ -z "${BPF_BASELINE_COMMIT}" ]; then
	echo "Error: bpf or bpf-next baseline commits are not provided"
	usage
fi

SUFFIX=$(date --utc +%Y-%m-%dT%H-%M-%S.%3NZ)
WORKDIR=$(pwd)
TMP_DIR=$(mktemp -d)

# shellcheck disable=SC2064
trap "cd ${WORKDIR}; exit" INT TERM EXIT

BPFTOOL_SRC_DIR="tools/bpf/bpftool"

declare -A PATH_MAP
PATH_MAP=(									\
	[${BPFTOOL_SRC_DIR}]=src						\
	[${BPFTOOL_SRC_DIR}/bash-completion]=bash-completion			\
	[${BPFTOOL_SRC_DIR}/Documentation]=docs					\
	[kernel/bpf/disasm.c]=src/kernel/bpf/disasm.c				\
	[kernel/bpf/disasm.h]=src/kernel/bpf/disasm.h				\
	[tools/include/tools/dis-asm-compat.h]=include/tools/dis-asm-compat.h	\
	[tools/include/uapi/asm-generic/bitsperlong.h]=include/uapi/asm-generic/bitsperlong.h	\
	[tools/include/uapi/linux/bpf_common.h]=include/uapi/linux/bpf_common.h	\
	[tools/include/uapi/linux/bpf.h]=include/uapi/linux/bpf.h		\
	[tools/include/uapi/linux/btf.h]=include/uapi/linux/btf.h		\
	[tools/include/uapi/linux/const.h]=include/uapi/linux/const.h		\
	[tools/include/uapi/linux/if_link.h]=include/uapi/linux/if_link.h	\
	[tools/include/uapi/linux/netlink.h]=include/uapi/linux/netlink.h	\
	[tools/include/uapi/linux/perf_event.h]=include/uapi/linux/perf_event.h	\
	[tools/include/uapi/linux/pkt_cls.h]=include/uapi/linux/pkt_cls.h	\
	[tools/include/uapi/linux/pkt_sched.h]=include/uapi/linux/pkt_sched.h	\
	[tools/include/uapi/linux/tc_act/tc_bpf.h]=include/uapi/linux/tc_act/tc_bpf.h	\
)

BPFTOOL_PATHS=( "${!PATH_MAP[@]}" )
BPFTOOL_VIEW_PATHS=( "${PATH_MAP[@]}" )
BPFTOOL_VIEW_EXCLUDE_REGEX='^(docs/\.gitignore|src/Makefile\.(feature|include))$'
LINUX_VIEW_EXCLUDE_REGEX='^$'

# Deal with tools/bpf/bpftool first, because once we've mkdir-ed src/, command
# "git mv" doesn't move bpftool _as_ src but _into_ src/.
BPFTOOL_TREE_FILTER="mkdir __bpftool && "$'\\\n'
BPFTOOL_TREE_FILTER+="git mv -kf ${BPFTOOL_SRC_DIR} __bpftool/${PATH_MAP[${BPFTOOL_SRC_DIR}]} && "$'\\\n'

# Extract bash-completion and Documentation from src/.
BPFTOOL_TREE_FILTER+="git mv -kf __bpftool/src/bash-completion __bpftool/bash-completion && "$'\\\n'
BPFTOOL_TREE_FILTER+="git mv -kf __bpftool/src/Documentation __bpftool/docs && "$'\\\n'

BPFTOOL_TREE_FILTER+="mkdir -p __bpftool/include/tools __bpftool/include/uapi/asm-generic __bpftool/include/uapi/linux/tc_act __bpftool/src/kernel/bpf && "$'\\\n'
for p in "${!PATH_MAP[@]}"; do
	case ${p} in
		${BPFTOOL_SRC_DIR}*)
			continue;;
	esac
	BPFTOOL_TREE_FILTER+="git mv -kf ${p} __bpftool/${PATH_MAP[${p}]} && "$'\\\n'
done
BPFTOOL_TREE_FILTER+="true >/dev/null"

cd_to()
{
	cd "${WORKDIR}" && cd "$1"
}

# Output brief single-line commit description
# $1 - commit ref
commit_desc()
{
	git log -n1 --pretty='%h ("%s")' "$1"
}

# Create commit single-line signature, which consists of:
# - full commit subject
# - author date in ISO8601 format
# - full commit body with newlines replaced with vertical bars (|)
# - shortstat appended at the end
# The idea is that this single-line signature is good enough to make final
# decision about whether two commits are the same, across different repos.
# $1 - commit ref
# $2 - paths filter
commit_signature()
{
	# shellcheck disable=SC2086
	git show --pretty='("%s")|%aI|%b' --shortstat "$1" -- ${2-.} | tr '\n' '|'
}

# Cherry-pick commits touching bpftool-related files
# $1 - baseline_tag
# $2 - tip_tag
cherry_pick_commits()
{
	local manual_mode=${MANUAL_MODE:-0}
	local baseline_tag=$1
	local tip_tag=$2
	local new_commits
	local signature
	local should_skip
	local synced_cnt
	local manual_check
	local bpftool_conflict_cnt
	local desc

	# shellcheck disable=SC2068
	new_commits=$(git rev-list --no-merges --topo-order --reverse "${baseline_tag}".."${tip_tag}" ${BPFTOOL_PATHS[@]})
	for new_commit in ${new_commits}; do
		if [[ "${baseline_tag}" == "${BPF_BASELINE_TAG}" ]]; then
			if git merge-base --is-ancestor "${new_commit}" "${BASELINE_COMMIT}"; then
				echo "Commit ${new_commit::12} from bpf is already in bpf-next branch, skipping."
				continue
			fi
		fi
		desc="$(commit_desc "${new_commit}")"
		signature="$(commit_signature "${new_commit}" "${BPFTOOL_PATHS[*]}")"
		# shellcheck disable=SC2126
		synced_cnt=$(grep -F "${signature}" "${TMP_DIR}"/bpftool_commits.txt | wc -l)
		manual_check=0
		if (("${synced_cnt}" > 0)); then
			# commit with the same subject is already in bpftool, but it's
			# not 100% the same commit, so check with user
			echo "Commit '${desc}' is synced into bpftool as:"
			grep -F "${signature}" "${TMP_DIR}"/bpftool_commits.txt | \
				cut -d'|' -f1 | sed -e 's/^/- /'
			if (("${manual_mode}" != 1 && "${synced_cnt}" == 1)); then
				echo "Skipping '${desc}' due to unique match..."
				continue
			fi
			if (("${synced_cnt}" > 1)); then
				echo "'${desc} matches multiple commits, please, double-check!"
				manual_check=1
			fi
		fi
		if (("${manual_mode}" == 1 || "${manual_check}" == 1)); then
			read -rp "Do you want to skip '${desc}'? [y/N]: " should_skip
			case "${should_skip}" in
				"y" | "Y")
					echo "Skipping '${desc}'..."
					continue
					;;
			esac
		fi
		# commit hasn't been synced into bpftool yet
		echo "Picking '${desc}'..."
		if ! git cherry-pick "${new_commit}" &>/dev/null; then
			echo "Warning! Cherry-picking '${desc} failed, checking if it's non-bpftool files causing problems..."
			# shellcheck disable=SC2068
			bpftool_conflict_cnt=$(git diff --name-only --diff-filter=U -- ${BPFTOOL_PATHS[@]} | wc -l)
			conflict_cnt=$(git diff --name-only | wc -l)
			prompt_resolution=1

			if (("${bpftool_conflict_cnt}" == 0)); then
				echo "Looks like only non-bpftool files have conflicts, ignoring..."
				if (("${conflict_cnt}" == 0)); then
					echo "Empty cherry-pick, skipping it..."
					git cherry-pick --abort
					continue
				fi

				git add .
				# GIT_EDITOR=true to avoid editor popping up to edit commit message
				if ! GIT_EDITOR=true git cherry-pick --continue &>/dev/null; then
					echo "Error! That still failed! Please resolve manually."
				else
					echo "Success! All cherry-pick conflicts were resolved for '${desc}'!"
					prompt_resolution=0
				fi
			fi

			if (("${prompt_resolution}" == 1)); then
				read -rp "Error! Cherry-picking '${desc}' failed, please fix manually and press <return> to proceed..."
			fi
		fi
		# Append signature of just cherry-picked commit to avoid
		# potentially cherry-picking the same commit twice later when
		# processing bpf tree commits. At this point we don't know yet
		# the final commit sha in bpftool repo, so we record Linux SHA
		# instead as LINUX_<sha>.
		echo "LINUX_$(git log --pretty='%h' -n1) ${signature}" >> "${TMP_DIR}"/bpftool_commits.txt
	done
}

cleanup()
{
	echo "Cleaning up..."
	rm -r -- "${TMP_DIR}"
	cd_to "${LINUX_REPO}"
	git checkout "${TIP_SYM_REF}"
	git branch -D "${BASELINE_TAG}" "${TIP_TAG}" "${BPF_BASELINE_TAG}" "${BPF_TIP_TAG}" \
		      "${SQUASH_BASE_TAG}" "${SQUASH_TIP_TAG}" || true
	# shellcheck disable=SC2015
	git show-ref --verify --quiet refs/heads/"${VIEW_TAG}" && \
		git branch -D "${VIEW_TAG}" || true

	cd_to .
	echo "DONE."
}

cd_to "${BPFTOOL_REPO}"
BPFTOOL_SYNC_TAG="bpftool-sync-${SUFFIX}"
git checkout -b "${BPFTOOL_SYNC_TAG}"

# Update libbpf
if [[ "${SKIP_LIBBPF_UPDATE:-0}" -ne 1 ]]; then
	cd_to "${BPFTOOL_REPO}"/libbpf
	git pull origin master
	LIBBPF_VERSION=$(grep -oE '^LIBBPF_([0-9.]+)' src/libbpf.map | sort -rV | head -n1 | cut -d'_' -f2)
	LIBBPF_COMMIT=$(git rev-parse HEAD)
	cd_to "${BPFTOOL_REPO}"
	if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
		git add libbpf
		git commit --signoff -m 'sync: Update libbpf submodule' \
			-m "\
Pull latest libbpf from mirror.
Libbpf version: ${LIBBPF_VERSION}
Libbpf commit:  ${LIBBPF_COMMIT}" \
			-- libbpf
	fi
fi

# Use libbpf's new checkpoints as tips
TIP_COMMIT=${BPF_NEXT_TIP_COMMIT:-$(cat "${BPFTOOL_REPO}"/libbpf/CHECKPOINT-COMMIT)}
BPF_TIP_COMMIT=${BPF_TIP_COMMIT:-$(cat "${BPFTOOL_REPO}"/libbpf/BPF-CHECKPOINT-COMMIT)}
if [ -z "${TIP_COMMIT}" ] || [ -z "${BPF_TIP_COMMIT}" ]; then
	echo "Error: bpf or bpf-next tip commits are not provided"
	usage
fi

cd_to "${BPFTOOL_REPO}"
GITHUB_ABS_DIR=$(pwd)
echo "Dumping existing bpftool commit signatures..."
for h in $(git log --pretty='%h' -n500); do
	echo "$h" "$(commit_signature "$h")" >> "${TMP_DIR}"/bpftool_commits.txt
done

# Use current kernel repo HEAD as a source of patches
cd_to "${LINUX_REPO}"
LINUX_ABS_DIR=$(pwd)
TIP_SYM_REF=$(git symbolic-ref -q --short HEAD || git rev-parse HEAD)
BASELINE_TAG="bpftool-baseline-${SUFFIX}"
TIP_TAG="bpftool-tip-${SUFFIX}"
BPF_BASELINE_TAG="bpftool-bpf-baseline-${SUFFIX}"
BPF_TIP_TAG="bpftool-bpf-tip-${SUFFIX}"
VIEW_TAG="bpftool-view-${SUFFIX}"

# Squash state of kernel repo at baseline into single commit
SQUASH_BASE_TAG="bpftool-squash-base-${SUFFIX}"
SQUASH_TIP_TAG="bpftool-squash-tip-${SUFFIX}"
SQUASH_COMMIT=$(git commit-tree "${BASELINE_COMMIT}^{tree}" -m "BASELINE SQUASH ${BASELINE_COMMIT}")

echo "WORKDIR:          ${WORKDIR}"
echo "LINUX REPO:       ${LINUX_REPO}"
echo "BPFTOOL REPO:     ${BPFTOOL_REPO}"
echo "TEMP DIR:         ${TMP_DIR}"
echo "SUFFIX:           ${SUFFIX}"
echo "BASE COMMIT:      '$(commit_desc "${BASELINE_COMMIT}")'"
echo "TIP COMMIT:       '$(commit_desc "${TIP_COMMIT}")'"
echo "BPF BASE COMMIT:  '$(commit_desc "${BPF_BASELINE_COMMIT}")'"
echo "BPF TIP COMMIT:   '$(commit_desc "${BPF_TIP_COMMIT}")'"
echo "SQUASH COMMIT:    ${SQUASH_COMMIT}"
echo "BASELINE TAG:     ${BASELINE_TAG}"
echo "TIP TAG:          ${TIP_TAG}"
echo "BPF BASELINE TAG: ${BPF_BASELINE_TAG}"
echo "BPF TIP TAG:      ${BPF_TIP_TAG}"
echo "SQUASH BASE TAG:  ${SQUASH_BASE_TAG}"
echo "SQUASH TIP TAG:   ${SQUASH_TIP_TAG}"
echo "VIEW TAG:         ${VIEW_TAG}"
echo "BPFTOOL SYNC TAG: ${BPFTOOL_SYNC_TAG}"
echo "PATCHES:          ${TMP_DIR}/patches"

git branch "${BASELINE_TAG}" "${BASELINE_COMMIT}"
git branch "${TIP_TAG}" "${TIP_COMMIT}"
git branch "${BPF_BASELINE_TAG}" "${BPF_BASELINE_COMMIT}"
git branch "${BPF_TIP_TAG}" "${BPF_TIP_COMMIT}"
git branch "${SQUASH_BASE_TAG}" "${SQUASH_COMMIT}"
git checkout -b "${SQUASH_TIP_TAG}" "${SQUASH_COMMIT}"

# Cherry-pick new commits onto squashed baseline commit
echo "Cherry-pick for bpf-next..."
cherry_pick_commits "${BASELINE_TAG}" "${TIP_TAG}"
echo "Cherry-pick for bpf..."
cherry_pick_commits "${BPF_BASELINE_TAG}" "${BPF_TIP_TAG}"

# Move all bpftool files into __bpftool directory.
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --prune-empty -f --tree-filter "${BPFTOOL_TREE_FILTER}" "${SQUASH_TIP_TAG}" "${SQUASH_BASE_TAG}"
# Make __bpftool a new root directory
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --prune-empty -f --subdirectory-filter __bpftool "${SQUASH_TIP_TAG}" "${SQUASH_BASE_TAG}"

# If there are no new commits with  bpftool-related changes, bail out
COMMIT_CNT=$(git rev-list --count "${SQUASH_BASE_TAG}".."${SQUASH_TIP_TAG}")
if (("${COMMIT_CNT}" <= 0)); then
	echo "No new changes to apply, we are done!"
	cleanup
	exit 2
fi

# Exclude baseline commit and generate nice cover letter with summary
git format-patch --no-signature "${SQUASH_BASE_TAG}".."${SQUASH_TIP_TAG}" --cover-letter -o "${TMP_DIR}"/patches

# Now is time to re-apply bpftool-related linux patches to bpftool repo
cd_to "${BPFTOOL_REPO}"

# shellcheck disable=SC2012
for patch in $(ls -1 "${TMP_DIR}"/patches | tail -n +2); do
	if ! git am --3way --committer-date-is-author-date "${TMP_DIR}/patches/${patch}"; then
		read -rp "Applying ${TMP_DIR}/patches/${patch} failed, please resolve manually and press <return> to proceed..."
	fi
done

# Use generated cover-letter as a template for "sync commit" with
# baseline and checkpoint commits from kernel repo (and leave summary
# from cover letter intact, of course)
echo "${TIP_COMMIT}" > CHECKPOINT-COMMIT &&					      \
echo "${BPF_TIP_COMMIT}" > BPF-CHECKPOINT-COMMIT &&				      \
git add CHECKPOINT-COMMIT &&							      \
git add BPF-CHECKPOINT-COMMIT &&						      \
awk '/\*\*\* BLURB HERE \*\*\*/ {p=1} p' "${TMP_DIR}"/patches/0000-cover-letter.patch | \
sed "s/\*\*\* BLURB HERE \*\*\*/\
sync: Pull latest bpftool changes from kernel\n\
\n\
Syncing latest bpftool commits from kernel repository.\n\
Baseline bpf-next commit:   ${BASELINE_COMMIT}\n\
Checkpoint bpf-next commit: ${TIP_COMMIT}\n\
Baseline bpf commit:        ${BPF_BASELINE_COMMIT}\n\
Checkpoint bpf commit:      ${BPF_TIP_COMMIT}/" |				      \
git commit --signoff --file=-

echo "SUCCESS! ${COMMIT_CNT} commits synced."

echo "Verifying Linux's and Github's bpftool state"

cd_to "${LINUX_REPO}"
git checkout -b "${VIEW_TAG}" "${TIP_COMMIT}"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --tree-filter "${BPFTOOL_TREE_FILTER}" "${VIEW_TAG}"^.."${VIEW_TAG}"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --subdirectory-filter __bpftool "${VIEW_TAG}"^.."${VIEW_TAG}"
# shellcheck disable=SC2068
git ls-files -- ${BPFTOOL_VIEW_PATHS[@]} | grep -v -E "${LINUX_VIEW_EXCLUDE_REGEX}" > "${TMP_DIR}"/linux-view.ls
# Before we compare each file, try to apply to the mirror a patch containing the
# expected differences between the two repositories; this is to avoid checking
# "known" differences visually and taking the risk of missing a new, relevant
# differences.
echo "Patching to account for expected differences..."
patch -d "${LINUX_ABS_DIR}" -p0 -f --reject-file=- --no-backup-if-mismatch < "${GITHUB_ABS_DIR}/scripts/sync-kernel-expected-diff.patch" || true
git add -u
git commit -m 'tmp: apply expected differences to compare github/kernel repos' || true

cd_to "${BPFTOOL_REPO}"
# shellcheck disable=SC2068
git ls-files -- ${BPFTOOL_VIEW_PATHS[@]} | grep -v -E "${BPFTOOL_VIEW_EXCLUDE_REGEX}" > "${TMP_DIR}"/github-view.ls

echo "Comparing list of files..."
diff -u "${TMP_DIR}"/linux-view.ls "${TMP_DIR}"/github-view.ls
echo "Comparing file contents..."
CONSISTENT=1
while IFS= read -r F; do
	if ! diff -u --color "${LINUX_ABS_DIR}/${F}" "${GITHUB_ABS_DIR}/${F}"; then
		echo "${LINUX_ABS_DIR}/${F} and ${GITHUB_ABS_DIR}/${F} are different!"
		CONSISTENT=0
	fi
done < "${TMP_DIR}"/linux-view.ls
echo ""
if (("${CONSISTENT}" == 1)); then
	echo "Great! Content is identical!"
else
	ignore_inconsistency=n
	echo "Unfortunately, there are some inconsistencies, please double check."
	echo "Some of them may come from patches in bpf tree but absent from bpf-next."
	echo "Note: I applied scripts/sync-kernel-expected-diff.patch before checking,"
	echo "to account for expected changes. If this patch needs an update,"
	echo "you can do it now with:"
	echo "------"
	echo "    (cd \"${LINUX_ABS_DIR}\" && git -c advice.detachedHead=false checkout HEAD~)"
	echo "    for f in \$(cat \"${TMP_DIR}/linux-view.ls\"); do"
	echo "        diff -u --label \"\${f}\" --label \"\${f}\" \\"
	echo "            \"${LINUX_ABS_DIR}/\${f}\" \\"
	echo "            \"${GITHUB_ABS_DIR}/\${f}\""
	echo "    done > \"${GITHUB_ABS_DIR}/scripts/sync-kernel-expected-diff.patch\""
	echo "------"
	read -rp "Does everything look good? [y/N]: " ignore_inconsistency
	case "${ignore_inconsistency}" in
		"y" | "Y")
			echo "Ok, proceeding..."
			;;
		*)
			echo "Oops, exiting with error..."
			exit 4
	esac
fi

cleanup
