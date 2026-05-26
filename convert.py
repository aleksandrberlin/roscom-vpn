#!/usr/bin/env python3
"""Convert domain lists (.txt) into sing-box rule-set files (.json + .srs)."""

import json
import struct
import sys
import zlib
from pathlib import Path

LISTS_DIR = Path("lists")
OUTPUT_JSON_DIR = Path("output/json")
OUTPUT_SRS_DIR = Path("output/srs")


def parse_domain_list(path: Path) -> list[str]:
    domains = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.append(line.lstrip(".").lower())
    return list(dict.fromkeys(domains))


def make_rule_set_json(domains: list[str]) -> dict:
    return {
        "version": 2,
        "rules": [{"domain_suffix": sorted(domains)}],
    }


# --- .srs binary compilation (pure Python, no sing-box binary needed) ---

_SRS_MAGIC = b"SRS"
_SRS_VERSION = 2
_RULE_DEFAULT = 0x00
_ITEM_FINAL = 0xFF
_ITEM_DOMAIN = 0x02
_ROOT_LABEL = 0x0A  # '\n' — marks domain_suffix in v2+


def _uvarint(value: int) -> bytes:
    buf = bytearray()
    while value >= 0x80:
        buf.append((value & 0x7F) | 0x80)
        value >>= 7
    buf.append(value)
    return bytes(buf)


class _Bitmap:
    """Bit array stored as uint64 words (LSB-first per word, big-endian serialization)."""

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
    """BFS-build a succinct trie from sorted byte-string keys."""
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
    buf.append(0)  # succinct set format version
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


def compile_srs(domains: list[str]) -> bytes:
    rule = bytearray()
    rule.append(_RULE_DEFAULT)
    rule.append(_ITEM_DOMAIN)
    rule.extend(_build_succinct_set(_domain_keys(domains)))
    rule.append(_ITEM_FINAL)
    rule.append(0x00)  # invert = false

    payload = bytearray(_uvarint(1))  # one rule
    payload.extend(rule)

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

    for txt_path in txt_files:
        name = txt_path.stem
        domains = parse_domain_list(txt_path)
        if not domains:
            print(f"Skipping empty list: {txt_path}")
            continue

        print(f"{name}: {len(domains)} domains")
        all_domains.extend(domains)

        (OUTPUT_JSON_DIR / f"{name}.json").write_text(
            json.dumps(make_rule_set_json(domains), indent=2) + "\n"
        )
        (OUTPUT_SRS_DIR / f"{name}.srs").write_bytes(compile_srs(domains))

    all_domains = list(dict.fromkeys(all_domains))
    print(f"all: {len(all_domains)} domains (combined)")

    (OUTPUT_JSON_DIR / "all.json").write_text(
        json.dumps(make_rule_set_json(all_domains), indent=2) + "\n"
    )
    (OUTPUT_SRS_DIR / "all.srs").write_bytes(compile_srs(all_domains))

    print("Done.")


if __name__ == "__main__":
    main()
