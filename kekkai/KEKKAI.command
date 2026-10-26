#!/bin/sh
# Finderからダブルクリックで起動（ターミナルが開きます）
cd "$(dirname "$0")" && exec ./kekkai serve
