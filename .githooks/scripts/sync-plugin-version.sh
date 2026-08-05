#!/bin/bash
#
# 把 .claude-plugin/plugin.json 的 version 欄位對齊 git tag。
#
# 版本的單一事實來源是 git tag（Go module 語意）；plugin.json 需要明文字串是因為
# Claude Code 的 plugin loader 讀不懂 git tag，所以由本腳本在 release 時反向寫入。
#
# 用法：
#   scripts/sync-plugin-version.sh              # 對齊目前可達的最新 tag
#   scripts/sync-plugin-version.sh patch        # 寫入下一個 patch 版本（commit 前用）
#   scripts/sync-plugin-version.sh minor|major  # 同上，遞增對應欄位
#
# 典型 release 流程：
#   scripts/sync-plugin-version.sh patch
#   git commit -am 'chore: release vX.Y.Z'
#   git push && git push --follow-tags   # 首次 push 由 pre-push hook 自動打 tag

set -euo pipefail

readonly PLUGIN_FILE=".claude-plugin/plugin.json"
readonly TAG_GLOB="v[0-9]*"

die() {
	echo "sync-plugin-version: $1" >&2
	exit 1
}

cd "$(git rev-parse --show-toplevel)" || die "不在 git repo 內"
[[ -f "$PLUGIN_FILE" ]] || die "找不到 ${PLUGIN_FILE}"

bump="${1:-none}"
case "$bump" in
none | patch | minor | major) ;;
*) die "未知參數 '${bump}'（可用：patch / minor / major，或不帶參數）" ;;
esac

tag="$(git describe --tags --abbrev=0 --match "$TAG_GLOB" 2>/dev/null || echo "v0.0.0")"
[[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || die "最新 tag 格式錯誤：${tag}"

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"

case "$bump" in
patch) patch=$((patch + 1)) ;;
minor)
	minor=$((minor + 1))
	patch=0
	;;
major)
	major=$((major + 1))
	minor=0
	patch=0
	;;
esac

version="${major}.${minor}.${patch}"
current="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PLUGIN_FILE" | head -1)"

if [[ "$current" == "$version" ]]; then
	echo "${PLUGIN_FILE} 已是 ${version}，無需變更"
	exit 0
fi

# 只改第一個 version 欄位，其餘 JSON 內容原樣保留。
# 走暫存檔而非 sed -i，因為 -i 的語法在 BSD(macOS) 與 GNU(Linux) 不相容。
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed "1,/\"version\"/s/\(\"version\"[[:space:]]*:[[:space:]]*\"\)[^\"]*\"/\1${version}\"/" \
	"$PLUGIN_FILE" >"$tmp"
cat "$tmp" >"$PLUGIN_FILE"

updated="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$PLUGIN_FILE" | head -1)"
[[ "$updated" == "$version" ]] || die "寫入失敗，${PLUGIN_FILE} 仍是 ${updated}"

echo "${PLUGIN_FILE}: ${current:-（空）} → ${version}（基準 tag ${tag}）"
