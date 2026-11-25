"""校验器：用于给正则命中的候选值做二次确认，压制误报。"""

from __future__ import annotations

import re


def luhn_ok(value: str) -> bool:
    """银行卡号 Luhn 校验。"""
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_CN_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_ID_CHECK = "10X98765432"


def cn_id_ok(value: str) -> bool:
    """中国大陆 18 位身份证校验位验证。"""
    v = value.strip().upper()
    if len(v) != 18 or not v[:17].isdigit():
        return False
    try:
        total = sum(int(v[i]) * w for i, w in enumerate(_CN_ID_WEIGHTS))
    except ValueError:
        return False
    return _CN_ID_CHECK[total % 11] == v[17]


def cn_mobile_ok(value: str) -> bool:
    """手机号段校验。"""
    return bool(re.fullmatch(r"1[3-9]\d{9}", value.strip()))


def mac_ok(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value.strip()))


VALIDATORS = {
    "luhn": luhn_ok,
    "cn_id": cn_id_ok,
    "cn_mobile": cn_mobile_ok,
    "mac": mac_ok,
}


def apply_validator(name: str | None, value: str) -> bool:
    """没有校验器时一律视为通过。"""
    if not name:
        return True
    fn = VALIDATORS.get(name)
    if fn is None:
        return True
    try:
        return bool(fn(value))
    except Exception:  # pragma: no cover - 校验器不应影响扫描
        return True
