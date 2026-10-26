#!/bin/sh
# Finderからダブルクリック: 初回はセットアップ（自動起動の登録まで）、2回目以降はダッシュボードを開く
cd "$(dirname "$0")" || exit 1
./kekkai open >/dev/null 2>&1 || exec ./kekkai setup
