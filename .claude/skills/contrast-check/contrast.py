#!/usr/bin/env python3
"""WCAG 2.x のコントラスト比を計算する（暗算や目測をしないための道具）。

使い方:
  python3 contrast.py <前景色> <背景色> [<前景色> <背景色> ...]
  色は #RRGGBB / #RGB / RRGGBB / rgb(r,g,b) で指定する。

計算式は WCAG 2.2 の定義（relative luminance と contrast ratio）どおり。
判定は丸めずに行う（例: 4.499:1 は 4.5:1 を満たさない）。
"""
import re
import sys

THRESHOLDS = [  # (名前, 必要な比)
    ("AA 通常の文字 (SC 1.4.3)", 4.5),
    ("AA 大きな文字 18pt以上/14pt太字以上 (SC 1.4.3)", 3.0),
    ("AA 文字以外のUI部品・図形 (SC 1.4.11)", 3.0),
    ("AAA 通常の文字 (SC 1.4.6)", 7.0),
    ("AAA 大きな文字 (SC 1.4.6)", 4.5),
]


def parse_color(text):
    s = text.strip().lower()
    m = re.fullmatch(r"rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)", s)
    if m:
        rgb = tuple(int(v) for v in m.groups())
    else:
        s = s.lstrip("#")
        if re.fullmatch(r"[0-9a-f]{3}", s):
            s = "".join(c * 2 for c in s)
        if not re.fullmatch(r"[0-9a-f]{6}", s):
            raise ValueError(f"色の形式が読めません: {text}")
        rgb = tuple(int(s[i:i + 2], 16) for i in (0, 2, 4))
    if any(v > 255 for v in rgb):
        raise ValueError(f"0〜255 の範囲外です: {text}")
    return rgb


def relative_luminance(rgb):
    def channel(v8):
        c = v8 / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (channel(v) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(fg, bg):
    l1, l2 = sorted((relative_luminance(fg), relative_luminance(bg)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


def main(argv):
    if len(argv) < 2 or len(argv) % 2:
        print(__doc__.strip())
        return 2
    for fg_text, bg_text in zip(argv[0::2], argv[1::2]):
        ratio = contrast_ratio(parse_color(fg_text), parse_color(bg_text))
        print(f"{fg_text} / {bg_text}: {ratio:.2f}:1（未丸め {ratio:.4f}）")
        for name, need in THRESHOLDS:
            print(f"  {'○' if ratio >= need else '×'} {name} 必要 {need}:1")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
