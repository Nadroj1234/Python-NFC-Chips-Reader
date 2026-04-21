from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple


SKYLANDER_IDS_PATH = Path(__file__).with_name("skylander_ids.md")

SKYLANDERS_SECTOR_COUNT = 16
SKYLANDERS_BLOCK_COUNT = 64
BLOCK_SIZE = 16

_KEY_POLY = 0x42F0E1EBA9EA3693
_KEY_MSB = 0x800000000000
_KEY_TRIM = 0xFFFFFFFFFFFF
_KEY_PRELOAD = 2 * 2 * 3 * 1103 * 12868356821
_SECTOR_ZERO_KEY = f"{73 * 2017 * 560381651:012x}"


@dataclass(frozen=True)
class SkylanderInfo:
    character_id: int
    variant_id: int
    name: str
    raw_dump: bytes
    decode_strategy: str = "block1-big"

    @property
    def uid_hex(self) -> str:
        return self.raw_dump[:4].hex().upper()

    def block_hex(self, block_index: int) -> str:
        start = block_index * BLOCK_SIZE
        end = start + BLOCK_SIZE
        return self.raw_dump[start:end].hex().upper()


def _pseudo_crc48(initial_value: int, data: bytes) -> int:
    crc = initial_value
    for value in data:
        crc ^= value << 40
        for _ in range(8):
            if crc & _KEY_MSB:
                crc = (crc << 1) ^ _KEY_POLY
            else:
                crc <<= 1
            crc &= _KEY_TRIM
    return crc


def calc_sector_key_a(uid_hex: str, sector: int) -> bytes:
    normalized_uid = uid_hex.strip().lower()
    if len(normalized_uid) != 8:
        raise ValueError("Skylanders tags use a 4-byte UID.")
    if sector < 0 or sector >= SKYLANDERS_SECTOR_COUNT:
        raise ValueError("Skylanders sector must be in the range 0-15.")

    if sector == 0:
        return bytes.fromhex(_SECTOR_ZERO_KEY)

    crc = _pseudo_crc48(_KEY_PRELOAD, bytes.fromhex(normalized_uid) + bytes([sector]))
    return crc.to_bytes(8, byteorder="little")[:6]


def parse_skylander_info(uid_hex: Optional[str], raw_dump: bytes) -> Optional[SkylanderInfo]:
    if uid_hex is None or len(raw_dump) < BLOCK_SIZE * 2:
        return None

    block_1 = raw_dump[BLOCK_SIZE:BLOCK_SIZE * 2]
    best = None
    for decode_strategy, character_id, variant_id in _candidate_ids_from_block_1(block_1):
        name = lookup_skylander_name(character_id, variant_id)
        if name.startswith("Unknown Skylander"):
            continue

        best = SkylanderInfo(
            character_id=character_id,
            variant_id=variant_id,
            name=name,
            raw_dump=raw_dump,
            decode_strategy=decode_strategy,
        )
        break

    if best is not None:
        return best

    # If no lookup matched, still return the primary decode so the user can see the raw IDs.
    character_id = int.from_bytes(block_1[0:2], byteorder="big")
    variant_id = int.from_bytes(block_1[12:14], byteorder="big")

    if uid_hex.upper() != raw_dump[:4].hex().upper():
        return None

    return SkylanderInfo(
        character_id=character_id,
        variant_id=variant_id,
        name=lookup_skylander_name(character_id, variant_id),
        raw_dump=raw_dump,
        decode_strategy="block1-big",
    )


def _candidate_ids_from_block_1(block_1: bytes) -> Iterable[Tuple[str, int, int]]:
    char_be = int.from_bytes(block_1[0:2], byteorder="big")
    char_le = int.from_bytes(block_1[0:2], byteorder="little")
    variant_be = int.from_bytes(block_1[12:14], byteorder="big")
    variant_le = int.from_bytes(block_1[12:14], byteorder="little")

    seen = set()
    candidates = [
        ("block1-big", char_be, variant_be),
        ("block1-char-little", char_le, variant_be),
        ("block1-variant-little", char_be, variant_le),
        ("block1-both-little", char_le, variant_le),
        ("block1-big-base-variant", char_be, 0),
        ("block1-char-little-base-variant", char_le, 0),
    ]

    for strategy, character_id, variant_id in candidates:
        key = (character_id, variant_id)
        if key in seen:
            continue
        seen.add(key)
        yield strategy, character_id, variant_id


def lookup_skylander_name(character_id: int, variant_id: int) -> str:
    data = load_skylander_name_map()
    exact_match = data.get((character_id, variant_id))
    if exact_match:
        return exact_match

    base_match = data.get((character_id, 0))
    if base_match:
        return f"{base_match} (variant {variant_id})"

    return f"Unknown Skylander ({character_id}/{variant_id})"


@lru_cache(maxsize=1)
def load_skylander_name_map() -> Dict[Tuple[int, int], str]:
    mapping: Dict[Tuple[int, int], str] = {}
    if not SKYLANDER_IDS_PATH.exists():
        return mapping

    for line in SKYLANDER_IDS_PATH.read_text(encoding="utf-8").splitlines():
        if "|" not in line:
            continue

        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) != 3:
            continue

        name, character_id_text, variant_id_text = cells
        if name == "Skylander":
            continue
        if not character_id_text.isdigit() or not variant_id_text.isdigit():
            continue

        mapping[(int(character_id_text), int(variant_id_text))] = name

    return mapping
