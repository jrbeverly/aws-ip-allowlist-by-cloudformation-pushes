"""Feed content normalization and validation for IPv4 CIDRs.

Accepts two feed formats: JSON arrays of CIDR strings and newline-delimited
text. Every retained entry must be a valid, canonical IPv4 CIDR. Duplicates
are removed and the result is sorted deterministically.
"""

import ipaddress
import json


class NormalizationError(Exception):
    """Base exception for normalization failures."""


class EmptyFeedError(NormalizationError):
    """Normalized result is empty — refusing to wipe the target resource."""


class InvalidCIDRError(NormalizationError):
    """A nonblank feed entry is not a valid IPv4 CIDR."""


def normalize_ipv4(content: str) -> list[str]:
    """Parse, validate, deduplicate, and sort IPv4 CIDRs from raw feed content.

    Detects format automatically:
    - Content starting with ``[`` (after trimming) is parsed as JSON.
    - Everything else is parsed as newline-delimited text.

    Args:
        content: Raw feed payload as a string.

    Returns:
        Deterministically sorted list of canonical IPv4 CIDR strings.

    Raises:
        EmptyFeedError: No valid entries remain after processing.
        InvalidCIDRError: A nonblank entry could not be parsed as an
            IPv4 CIDR or has host bits set.
    """
    entries = _parse_entries(content)
    if not entries:
        raise EmptyFeedError("Feed produced no entries after parsing.")

    validated = []
    for lineno, raw in entries:
        cidr = _validate_ipv4_cidr(raw, lineno)
        validated.append(cidr)

    unique = list(dict.fromkeys(validated))
    unique.sort(key=lambda c: ipaddress.IPv4Network(c, strict=False))
    return [str(n) for n in unique]


def _parse_entries(content: str) -> list[tuple[int, str]]:
    """Extract raw entry strings from feed content.

    Returns a list of ``(line_number, stripped_entry)`` tuples. Line
    numbers are 0-based for JSON (array index) and 1-based for text.

    Raises:
        InvalidCIDRError: The content looks like JSON but cannot be
            parsed as a flat array of strings.
    """
    trimmed = content.strip()
    if trimmed.startswith("[") or trimmed.startswith("{"):
        return _parse_json(trimmed)
    return _parse_text(content)


def _parse_json(text: str) -> list[tuple[int, str]]:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidCIDRError(
            f"Feed appears to be JSON but could not be parsed: {exc}"
        ) from exc

    if not isinstance(raw, list):
        raise InvalidCIDRError(
            f"Expected a JSON array of CIDR strings, got {type(raw).__name__}"
        )

    entries: list[tuple[int, str]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, str):
            raise InvalidCIDRError(
                f"JSON entry [{i}] is not a string: {item!r}"
            )
        entry = item.strip()
        if entry:
            entries.append((i, entry))
    return entries


def _parse_text(content: str) -> list[tuple[int, str]]:
    entries: list[tuple[int, str]] = []
    for lineno, line in enumerate(content.split("\n"), start=1):
        stripped = line.strip()
        if stripped:
            entries.append((lineno, stripped))
    return entries


def _validate_ipv4_cidr(raw: str, lineno: int) -> ipaddress.IPv4Network:
    if "/" not in raw:
        raise InvalidCIDRError(
            f"Entry on line {lineno} is not a valid IPv4 CIDR "
            f"(missing prefix length): {raw!r}"
        )
    try:
        return ipaddress.IPv4Network(raw, strict=True)
    except (ValueError, TypeError) as exc:
        raise InvalidCIDRError(
            f"Entry on line {lineno} is not a valid IPv4 CIDR: {raw!r}"
        ) from exc
