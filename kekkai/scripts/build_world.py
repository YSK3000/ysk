#!/usr/bin/env python3
"""Build kekkai/web/data/world.json from world-atlas (Natural Earth 110m) + i18n-iso-countries.

    npm pack world-atlas@2.0.2 i18n-iso-countries  (extract both)
    python3 scripts/build_world.py <world-atlas>/countries-110m.json <i18n-iso-countries dir> out.json

Output: [{"a2": "JP", "n": "日本", "p": [[[lon, lat], ...], ...]}] with rings cut at the antimeridian
so the browser can project them with a plain planar projection. Antarctica is omitted.
"""
import json
import sys


def decode_arcs(topo):
    sx, sy = topo["transform"]["scale"]
    tx, ty = topo["transform"]["translate"]
    out = []
    for arc in topo["arcs"]:
        x = y = 0
        pts = []
        for dx, dy in arc:
            x += dx
            y += dy
            pts.append((x * sx + tx, y * sy + ty))
        out.append(pts)
    return out


def ring(idxs, arcs):
    pts = []
    for i in idxs:
        a = arcs[i] if i >= 0 else list(reversed(arcs[~i]))
        pts.extend(a if not pts else a[1:])
    return pts


def cut_antimeridian(pts):
    """Split a ring wherever it jumps across ±180°; close each piece along the meridian."""
    pieces = [[pts[0]]]
    crossings = 0
    for (lon1, lat1), (lon2, lat2) in zip(pts, pts[1:]):
        if abs(lon2 - lon1) > 180:
            crossings += 1
            edge = 180 if lon1 > 0 else -180
            lon2u = lon2 + 360 if lon1 > 0 else lon2 - 360
            t = (edge - lon1) / (lon2u - lon1) if lon2u != lon1 else 0
            latc = lat1 + t * (lat2 - lat1)
            pieces[-1].append((edge, latc))
            pieces.append([(-edge, latc)])
        pieces[-1].append((lon2, lat2))
    if crossings == 0:
        return [pts]
    if len(pieces) > 1:
        pieces[0] = pieces.pop() + pieces[0][1:]
    return [p + [p[0]] for p in pieces if len(p) >= 3]


def main():
    topo = json.load(open(sys.argv[1]))
    base = sys.argv[2].rstrip("/")
    codes = json.load(open(base + "/codes.json"))
    num2a2 = {c[2]: c[0] for c in codes}
    ja = json.load(open(base + "/langs/ja.json"))["countries"]
    arcs = decode_arcs(topo)
    out = []
    for g in topo["objects"]["countries"]["geometries"]:
        a2 = num2a2.get(g.get("id", ""), "")
        if a2 == "AQ":
            continue
        name_en = (g.get("properties") or {}).get("name", "")
        name = ja.get(a2)
        if isinstance(name, list):
            name = name[0]
        polys = g["arcs"] if g["type"] == "MultiPolygon" else [g["arcs"]] if g["type"] == "Polygon" else []
        rings = []
        for poly in polys:
            for r in poly:
                for piece in cut_antimeridian(ring(r, arcs)):
                    rings.append([[round(x, 2), round(y, 2)] for x, y in piece])
        out.append({"a2": a2, "n": name or name_en, "p": rings})
    json.dump(out, open(sys.argv[3], "w"), ensure_ascii=False, separators=(",", ":"))
    print("countries:", len(out), "rings:", sum(len(c["p"]) for c in out),
          "points:", sum(len(r) for c in out for r in c["p"]))


if __name__ == "__main__":
    main()
