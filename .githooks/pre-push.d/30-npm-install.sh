#!/bin/bash
#
# pre-push.d/30-npm-install: 推 master 時在背景跑 pnpm run install 裝本專案的指令 (package.json 有宣告才跑)。
#
# 細節見 scripts/npm-run.sh; 排在 40-npm-deploy 之前, 兩者依序執行。

exec "$(dirname "$0")/../scripts/npm-run.sh" install
