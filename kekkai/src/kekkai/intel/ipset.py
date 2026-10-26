"""Compact IP range set (merged intervals + bisect) for threat-feed membership tests."""
from __future__ import annotations

import bisect
import ipaddress
from typing import Iterable, List, Tuple


class IPSet:
    def __init__(self, entries: Iterable[str] = ()):
        self._starts = {4: [], 6: []}  # type: dict
        self._ends = {4: [], 6: []}  # type: dict
        self.count = 0
        ranges = {4: [], 6: []}  # type: dict
        for e in entries:
            e = e.strip()
            if not e:
                continue
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            ranges[net.version].append((int(net.network_address), int(net.broadcast_address)))
            self.count += 1
        for v in (4, 6):
            merged = _merge(ranges[v])
            self._starts[v] = [a for a, _ in merged]
            self._ends[v] = [b for _, b in merged]

    def __contains__(self, address: object) -> bool:
        try:
            ip = ipaddress.ip_address(str(address))
        except ValueError:
            return False
        starts = self._starts[ip.version]
        n = int(ip)
        i = bisect.bisect_right(starts, n) - 1
        return i >= 0 and n <= self._ends[ip.version][i]

    def __len__(self) -> int:
        return self.count


def _merge(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    ranges.sort()
    out: List[Tuple[int, int]] = []
    for a, b in ranges:
        if out and a <= out[-1][1] + 1:
            if b > out[-1][1]:
                out[-1] = (out[-1][0], b)
        else:
            out.append((a, b))
    return out
