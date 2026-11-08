"""Defense-in-depth helpers: input canonicalization and admin API-key auth."""

from __future__ import annotations

import hmac
import os
import re
import unicodedata
from typing import Optional

from fastapi import Header, HTTPException, status

ZERO_WIDTH_CHARS = {"​", "‌", "‍", "⁠", "﻿", "­"}

# Common Cyrillic/Greek look-alikes that NFKD leaves untouched.
HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ո": "n",
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
        "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t",
        "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
        "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    }
)

_WORD_GAP = re.compile(r"\s{2,}")
_LETTER_SPACED = re.compile(r"^(?:\S )+\S$")
_WHITESPACE = re.compile(r"\s+")


def _is_hidden(char: str) -> bool:
    if char in ZERO_WIDTH_CHARS:
        return True
    category = unicodedata.category(char)
    if category == "Mn":  # combining marks split off by NFKD (e.g. accents)
        return True
    if category in ("Cc", "Cf", "Co", "Cn"):
        return not char.isspace()
    return False


def _join_letter_spaced(text: str) -> str:
    """Rejoin 'i g n o r e  a l l' style obfuscation into 'ignore all'."""
    chunks = _WORD_GAP.split(text)
    if len(chunks) == 1 and not _LETTER_SPACED.match(text.strip()):
        return text
    joined = [
        chunk.replace(" ", "") if _LETTER_SPACED.match(chunk.strip()) else chunk
        for chunk in chunks
    ]
    return " ".join(joined)


def canonicalize_text(text: str) -> str:
    """Normalize a prompt so obfuscated attacks hit the same regex signals."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not _is_hidden(ch))
    text = text.translate(HOMOGLYPHS)
    text = _join_letter_spaced(text)
    return _WHITESPACE.sub(" ", text).strip()


def verify_admin_key(x_admin_key: Optional[str] = Header(None)) -> None:
    expected = os.getenv("ADMIN_API_KEY", "dev-admin-secret-key")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Admin-Key",
        )
