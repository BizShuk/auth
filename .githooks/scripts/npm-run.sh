#!/bin/bash
#
# scripts/npm-run.sh: pre-push.d/*-npm-*.sh 共用的 `pnpm run <script>` 背景執行器。
#
# 用法 (由 pre-push 子腳本呼叫, stdin 是 git 給 pre-push 的 ref 清單):
#   scripts/npm-run.sh <npm-script>
#
# 只在這次 push 帶了新的 master commit, 且 package.json 宣告了 <npm-script> 時才動作。
# 執行在背景, push 不會變慢; 同一個 repo 的多支 npm 腳本以 mkdir lock 依序執行,
# 所以 install 一定在 deploy 之前跑完 (pre-push.d 的檔名順序)。
# 跑的是`工作目錄`, 不是被 push 的 commit: 這是把自己剛改的東西裝回自己的機器。
# log 在 ~/.config/inf/logs/npm-<repo>.log。永遠 exit 0, 不擋 push。

set -uo pipefail

readonly RELEASE_BRANCH="master"
readonly PACKAGE_FILE="package.json"

script="${1:?usage: npm-run.sh <npm-script>}"
note() { echo "pre-push: $1" >&2; }

pushes_new_master() {
	local local_ref local_sha remote_sha
	while read -r local_ref local_sha _ remote_sha; do
		[[ "$local_ref" == "refs/heads/${RELEASE_BRANCH}" ]] || continue
		[[ "$local_sha" =~ ^0+$ ]] && continue
		[[ "$remote_sha" =~ ^0+$ ]] && return 0
		git rev-list "${remote_sha}..${local_sha}" 2>/dev/null | grep -q . && return 0
	done
	return 1
}

pushes_new_master || exit 0
[[ -f "$PACKAGE_FILE" ]] || exit 0
command -v jq >/dev/null 2>&1 || { note "沒有 jq, 略過 pnpm run ${script}"; exit 0; }
jq -e --arg s "$script" '.scripts[$s] // empty' "$PACKAGE_FILE" >/dev/null || exit 0
command -v pnpm >/dev/null 2>&1 || { note "沒有 pnpm, 略過 pnpm run ${script}"; exit 0; }

repo="$(basename "$(git rev-parse --show-toplevel)")"
log_dir="${HOME}/.config/inf/logs"
lock="${HOME}/.config/inf/npm-${repo}.lock"
log="${log_dir}/npm-${repo}.log"
mkdir -p "$log_dir"

(
	until mkdir "$lock" 2>/dev/null; do sleep 1; done
	trap 'rmdir "$lock"' EXIT
	echo "=== $(date '+%F %T') pnpm run ${script} ==="
	if pnpm run "$script"; then
		echo "=== ok: pnpm run ${script} ==="
	else
		echo "=== FAILED ($?): pnpm run ${script} ==="
	fi
) </dev/null >>"$log" 2>&1 &
disown

note "背景執行 pnpm run ${script}, log: ${log}"
exit 0
