"""Tests for normalizer.py — IPv4 CIDR normalization and validation."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from normalizer import (
    EmptyFeedError,
    InvalidCIDRError,
    NormalizationError,
    normalize_ipv4,
)


# ── Text format ──────────────────────────────────────────────────────────────

def test_text_single_cidr():
    result = normalize_ipv4("10.0.0.0/8")
    assert result == ["10.0.0.0/8"]


def test_text_multiple_cidrs():
    result = normalize_ipv4("10.0.0.0/8\n192.168.0.0/16\n172.16.0.0/12")
    assert result == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def test_text_trims_whitespace():
    result = normalize_ipv4("  10.0.0.0/8  \n\t192.168.0.0/16\t")
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_text_ignores_blank_lines():
    result = normalize_ipv4("10.0.0.0/8\n\n\n192.168.0.0/16\n\n")
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_text_ignores_whitespace_only_lines():
    result = normalize_ipv4("10.0.0.0/8\n   \n\t\n192.168.0.0/16")
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_text_deduplicates():
    result = normalize_ipv4("10.0.0.0/8\n192.168.0.0/16\n10.0.0.0/8\n192.168.0.0/16")
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_text_sorts_deterministically():
    result = normalize_ipv4("192.168.0.0/16\n10.0.0.0/8\n172.16.0.0/12")
    assert result == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def test_text_same_prefix_sorted_by_network():
    result = normalize_ipv4("192.168.3.0/24\n192.168.1.0/24\n192.168.2.0/24")
    assert result == ["192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24"]


def test_text_slash_32_single_host():
    result = normalize_ipv4("192.168.1.1/32")
    assert result == ["192.168.1.1/32"]


def test_text_slash_0_default_route():
    result = normalize_ipv4("0.0.0.0/0")
    assert result == ["0.0.0.0/0"]


# ── JSON format ──────────────────────────────────────────────────────────────

def test_json_array_of_cidrs():
    result = normalize_ipv4('["10.0.0.0/8", "192.168.0.0/16"]')
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_json_single_cidr():
    result = normalize_ipv4('["10.0.0.0/8"]')
    assert result == ["10.0.0.0/8"]


def test_json_deduplicates():
    result = normalize_ipv4('["10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8"]')
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_json_sorts_deterministically():
    result = normalize_ipv4('["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]')
    assert result == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def test_json_trims_whitespace_in_entries():
    result = normalize_ipv4('["  10.0.0.0/8  ", "192.168.0.0/16"]')
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


def test_json_ignores_empty_strings_after_trim():
    result = normalize_ipv4('["10.0.0.0/8", "", "  ", "192.168.0.0/16"]')
    assert result == ["10.0.0.0/8", "192.168.0.0/16"]


# ── Format detection ─────────────────────────────────────────────────────────

def test_detects_json_by_leading_bracket():
    result = normalize_ipv4('["10.0.0.0/8"]')
    assert result == ["10.0.0.0/8"]


def test_detects_json_even_with_leading_whitespace():
    result = normalize_ipv4('\n  ["10.0.0.0/8"]')
    assert result == ["10.0.0.0/8"]


def test_text_starting_with_bracket_like_string_is_json_parse_error():
    """Content that starts with [ is routed to the JSON parser and fails there."""
    with pytest.raises(InvalidCIDRError, match="could not be parsed"):
        normalize_ipv4("[not json]")


# ── Empty feed errors ────────────────────────────────────────────────────────

def test_empty_string_raises_empty_feed():
    with pytest.raises(EmptyFeedError, match="no entries"):
        normalize_ipv4("")


def test_whitespace_only_raises_empty_feed():
    with pytest.raises(EmptyFeedError, match="no entries"):
        normalize_ipv4("   \n\t\n  ")


def test_empty_json_array_raises_empty_feed():
    with pytest.raises(EmptyFeedError, match="no entries"):
        normalize_ipv4("[]")


def test_json_array_of_only_empty_strings_raises_empty_feed():
    with pytest.raises(EmptyFeedError, match="no entries"):
        normalize_ipv4('["", "  ", ""]')


# ── Invalid CIDR errors ──────────────────────────────────────────────────────

def test_invalid_ip_octet_out_of_range():
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("10.0.0.256/8")


def test_invalid_not_a_cidr():
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("just-a-string")


def test_invalid_host_bits_set():
    """IPv4Network strict mode rejects CIDRs with host bits set."""
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("10.0.0.1/8")


def test_invalid_missing_prefix():
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("10.0.0.0")


def test_invalid_prefix_too_large():
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("10.0.0.0/33")


def test_invalid_ipv6_in_ipv4_feed():
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("::/0")


def test_invalid_mixed_valid_and_invalid():
    """One invalid entry in a text feed fails the entire batch."""
    with pytest.raises(InvalidCIDRError, match="not a valid IPv4 CIDR"):
        normalize_ipv4("10.0.0.0/8\ninvalid\n192.168.0.0/16")


def test_invalid_empty_json_entry_with_nonempty_invalid():
    """A non-string JSON entry causes failure."""
    with pytest.raises(InvalidCIDRError, match="not a string"):
        normalize_ipv4('["10.0.0.0/8", 42]')


# ── Malformed JSON ───────────────────────────────────────────────────────────

def test_json_not_an_array():
    with pytest.raises(InvalidCIDRError, match="Expected a JSON array"):
        normalize_ipv4('{"cidrs": ["10.0.0.0/8"]}')


def test_json_unparseable():
    with pytest.raises(InvalidCIDRError, match="could not be parsed"):
        normalize_ipv4('[broken json')


# ── Exception hierarchy ──────────────────────────────────────────────────────

def test_empty_feed_is_normalization_error():
    assert issubclass(EmptyFeedError, NormalizationError)


def test_invalid_cidr_is_normalization_error():
    assert issubclass(InvalidCIDRError, NormalizationError)


def test_normalization_errors_caught_generically():
    with pytest.raises(NormalizationError):
        normalize_ipv4("")
    with pytest.raises(NormalizationError):
        normalize_ipv4("not-a-cidr")


# ── Edge cases ───────────────────────────────────────────────────────────────

def test_duplicates_across_different_whitespace():
    """Same CIDR with different whitespace should deduplicate."""
    result = normalize_ipv4("  10.0.0.0/8\n10.0.0.0/8  \n\t10.0.0.0/8\t")
    assert result == ["10.0.0.0/8"]


def test_large_feed():
    """Smoke test that a moderately large feed works."""
    cidrs = [f"10.{i}.{j}.0/24" for i in range(5) for j in range(5)]
    content = "\n".join(cidrs)
    result = normalize_ipv4(content)
    assert len(result) == 25
    assert result == sorted(result)


def test_result_is_list_of_strings():
    result = normalize_ipv4("10.0.0.0/8\n192.168.0.0/16")
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, str)
