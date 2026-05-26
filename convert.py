#!/usr/bin/env python3
"""Convert domain lists (.txt) into sing-box rule-set files (.json + .srs)."""

import ipaddress
import json
import struct
import sys
import zlib
from pathlib import Path

LISTS_DIR = Path("lists")
OUTPUT_JSON_DIR = Path("output/json")
OUTPUT_SRS_DIR = Path("output/srs")


def _is_ip_cidr(line: str) -> bool:
    try:
        ipaddress.ip_network(line, strict=False)
        return True
    except ValueError:
        return False


def parse_list(path: Path) -> tuple[list[str], list[str]]:
    domains = []
    cidrs = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _is_ip_cidr(line):
            cidrs.append(str(ipaddress.ip_network(line, strict=False)))
        else:
            domains.append(line.lstrip(".").lower())
    return list(dict.fromkeys(domains)), list(dict.fromkeys(cidrs))


def make_rule_set_json(domains: list[str], cidrs: list[str]) -> dict:
    rules = []
    if domains:
        rules.append({"domain_suffix": sorted(domains)})
    if cidrs:
        rules.append({"ip_cidr": sorted(cidrs)})
    return {"version": 2, "rules": rules}


# --- .srs binary compilation (pure Python, no sing-box binary needed) ---

_SRS_MAGIC = b"SRS"
_SRS_VERSION = 2
_RULE_DEFAULT = 0x00
_ITEM_FINAL = 0xFF
_ITEM_DOMAIN = 0x02
_ITEM_IP_CIDR = 0x06
_ROOT_LABEL = 0x0A


def _uvarint(value: int) -> bytes:
    buf = bytearray()
    while value >= 0x80:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value)
    return bytes(buf)


class _Bitmap:
    def __init__(self):
        self._words: list[int] = []
        self._count = 0

    def append(self, bit: int):
        w = self._count >> 6
        if w >= len(self._words):
            self._words.append(0)
        if bit:
            self._words[w] |= 1 << (self._count & 63)
        self._count += 1

    def serialize(self) -> bytes:
        buf = bytearray(_uvarint(len(self._words)))
        for w in self._words:
            buf.extend(struct.pack(">Q", w))
        return bytes(buf)


def _build_succinct_set(keys: list[bytes]) -> bytes:
    leaves = _Bitmap()
    label_bm = _Bitmap()
    labels = bytearray()

    queue: list[tuple[int, int, int]] = [(0, len(keys), 0)]
    while queue:
        next_q: list[tuple[int, int, int]] = []
        for start, end, depth in queue:
            has_leaf = False
            i = start
            while i < end:
                if depth >= len(keys[i]):
                    has_leaf = True
                    i += 1
                    continue
                ch = keys[i][depth]
                j = i + 1
                while j < end and depth < len(keys[j]) and keys[j][depth] == ch:
                    j += 1
                labels.append(ch)
                label_bm.append(0)
                next_q.append((i, j, depth + 1))
                i = j
            leaves.append(1 if has_leaf else 0)
            label_bm.append(1)
        queue = next_q

    buf = bytearray()
    buf.append(0)
    buf.extend(leaves.serialize())
    buf.extend(label_bm.serialize())
    buf.extend(_uvarint(len(labels)))
    buf.extend(labels)
    return bytes(buf)


def _domain_keys(domains: list[str]) -> list[bytes]:
    keys = []
    for d in domains:
        raw = chr(_ROOT_LABEL) + d
        keys.append(raw[::-1].encode())
    keys.sort()
    return keys


def _cidrs_to_ranges(cidrs: list[str]) -> list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]
    networks = list(ipaddress.collapse_addresses(sorted(networks, key=lambda n: (n.version, n.network_address.packed))))

    ranges = []
    for net in networks:
        ranges.append((net.network_address, net.broadcast_address))

    merged = []
    for start, end in sorted(ranges, key=lambda r: r[0].packed):
        if merged and start.version == merged[-1][0].version and int(start) <= int(merged[-1][1]) + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _encode_ip_set(cidrs: list[str]) -> bytes:
    ranges = _cidrs_to_ranges(cidrs)
    buf = bytearray()
    buf.append(_ITEM_IP_CIDR)
    buf.append(1)  # IP set version
    buf.extend(struct.pack(">Q", len(ranges)))
    for start, end in ranges:
        addr_from = start.packed
        addr_to = end.packed
        buf.extend(_uvarint(len(addr_from)))
        buf.extend(addr_from)
        buf.extend(_uvarint(len(addr_to)))
        buf.extend(addr_to)
    return bytes(buf)


def compile_srs(domains: list[str], cidrs: list[str]) -> bytes:
    rules = []

    if domains:
        rule = bytearray()
        rule.append(_RULE_DEFAULT)
        rule.append(_ITEM_DOMAIN)
        rule.extend(_build_succinct_set(_domain_keys(domains)))
        rule.append(_ITEM_FINAL)
        rule.append(0x00)
        rules.append(rule)

    if cidrs:
        rule = bytearray()
        rule.append(_RULE_DEFAULT)
        rule.extend(_encode_ip_set(cidrs))
        rule.append(_ITEM_FINAL)
        rule.append(0x00)
        rules.append(rule)

    payload = bytearray(_uvarint(len(rules)))
    for r in rules:
        payload.extend(r)

    header = bytearray(_SRS_MAGIC)
    header.append(_SRS_VERSION)
    header.extend(zlib.compress(bytes(payload), 9))
    return bytes(header)


# --- Main ---


def main():
    if not LISTS_DIR.exists():
        print(f"No {LISTS_DIR}/ directory found", file=sys.stderr)
        sys.exit(1)

    txt_files = sorted(LISTS_DIR.glob("*.txt"))
    if not txt_files:
        print(f"No .txt files in {LISTS_DIR}/", file=sys.stderr)
        sys.exit(1)

    OUTPUT_JSON_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_SRS_DIR.mkdir(parents=True, exist_ok=True)

    all_domains: list[str] = []
    all_cidrs: list[str] = []

    for txt_path in txt_files:
        name = txt_path.stem
        domains, cidrs = parse_list(txt_path)
        if not domains and not cidrs:
            print(f"Skipping empty list: {txt_path}")
            continue

        parts = []
        if domains:
            parts.append(f"{len(domains)} domains")
        if cidrs:
            parts.append(f"{len(cidrs)} CIDRs")
        print(f"{name}: {', '.join(parts)}")

        all_domains.extend(domains)
        all_cidrs.extend(cidrs)

        (OUTPUT_JSON_DIR / f"{name}.json").write_text(
            json.dumps(make_rule_set_json(domains, cidrs), indent=2) + "\n"
        )
        (OUTPUT_SRS_DIR / f"{name}.srs").write_bytes(compile_srs(domains, cidrs))

    all_domains = list(dict.fromkeys(all_domains))
    all_cidrs = list(dict.fromkeys(all_cidrs))
    parts = []
    if all_domains:
        parts.append(f"{len(all_domains)} domains")
    if all_cidrs:
        parts.append(f"{len(all_cidrs)} CIDRs")
    print(f"all: {', '.join(parts)} (combined)")

    (OUTPUT_JSON_DIR / "all.json").write_text(
        json.dumps(make_rule_set_json(all_domains, all_cidrs), indent=2) + "\n"
    )
    (OUTPUT_SRS_DIR / "all.srs").write_bytes(compile_srs(all_domains, all_cidrs))

    print("Done.")


if __name__ == "__main__":
    main()
