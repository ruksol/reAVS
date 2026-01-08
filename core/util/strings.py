from __future__ import annotations

import math
import re
from typing import Iterable

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log(p, 2)
    return entropy


def is_base64ish(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    if len(value) % 4 != 0:
        return False
    if not _BASE64_RE.match(value):
        return False
    return shannon_entropy(value) >= 3.0


def any_base64ish(strings: Iterable[str]) -> bool:
    return any(is_base64ish(s) for s in strings)


def is_hexish(value: str) -> bool:
    if not value or len(value) < 16:
        return False
    if len(value) % 2 != 0:
        return False
    return bool(_HEX_RE.match(value))


def desc_to_fqcn(value: str | None) -> str | None:
    if not value:
        return None
    if "->" in value:
        return value
    name = value
    array_dims = 0
    while name.startswith("["):
        array_dims += 1
        name = name[1:]
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    if "/" in name:
        name = name.replace("/", ".")
    if array_dims:
        name = name + "[]" * array_dims
    return name


def fqcn_to_desc(value: str | None) -> str | None:
    if not value:
        return None
    if "->" in value:
        return value
    name = value
    array_dims = 0
    while name.endswith("[]"):
        array_dims += 1
        name = name[:-2]
    if name.startswith("L") and name.endswith(";"):
        return value
    name = name.replace(".", "/")
    desc = f"L{name};"
    if array_dims:
        return "[" * array_dims + desc
    return desc


def normalize_component_name(value: str | None) -> str | None:
    return desc_to_fqcn(value)


def normalize_method_name(value: str | None) -> str | None:
    if not value:
        return None
    if "->" in value:
        owner, rest = value.split("->", 1)
        owner = desc_to_fqcn(owner) or owner
        return f"{owner}->{rest}"
    return desc_to_fqcn(value)
