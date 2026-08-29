"""Tests for discovery.py — target resolution from deployment context."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from discovery import (
    SyncTarget,
    ResourceKind,
    AddressFamily,
    WafScope,
    resolve_targets,
)


# ── WAF Regional ────────────────────────────────────────────────────────────

def _waf_regional_config(*, ipv4=True, ipv6=False):
    return {
        "feed_name": "my-feed",
        "source_type": "HTTP",
        "source_location": "https://example.com/ips.txt",
        "parameter_path_root": "/ip-allowlist/",
        "publish_arn": "true",
        "publish_id": "true",
        "stack_name": "my-feed-sync",
        "update_role_arn": "arn:aws:iam::123456789012:role/my-feed-update-role-us-east-1",
        "waf_scope": "REGIONAL",
        "waf_ipv4_ipset_id": "ipset-ipv4-id" if ipv4 else "",
        "waf_ipv4_ipset_name": "my-feed-ipv4" if ipv4 else "",
        "waf_ipv6_ipset_id": "ipset-ipv6-id" if ipv6 else "",
        "waf_ipv6_ipset_name": "my-feed-ipv6" if ipv6 else "",
        "resource_kind": "",
        "pl_ipv4_list_id": "",
        "pl_ipv4_list_name": "",
        "pl_ipv6_list_id": "",
        "pl_ipv6_list_name": "",
    }


def test_waf_regional_ipv4_only():
    targets = resolve_targets(_waf_regional_config(ipv4=True, ipv6=False))
    assert len(targets) == 1
    t = targets[0]
    assert t.resource_kind == ResourceKind.WAF_IP_SET
    assert t.address_family == AddressFamily.IPV4
    assert t.scope == WafScope.REGIONAL
    assert t.resource_id == "ipset-ipv4-id"
    assert t.resource_name == "my-feed-ipv4"
    assert t.managed_properties == ["Addresses"]


def test_waf_regional_ipv6_only():
    targets = resolve_targets(_waf_regional_config(ipv4=False, ipv6=True))
    assert len(targets) == 1
    t = targets[0]
    assert t.resource_kind == ResourceKind.WAF_IP_SET
    assert t.address_family == AddressFamily.IPV6
    assert t.scope == WafScope.REGIONAL
    assert t.resource_id == "ipset-ipv6-id"
    assert t.managed_properties == ["Addresses"]


def test_waf_regional_dual_stack():
    targets = resolve_targets(_waf_regional_config(ipv4=True, ipv6=True))
    assert len(targets) == 2
    families = {t.address_family for t in targets}
    assert families == {AddressFamily.IPV4, AddressFamily.IPV6}
    for t in targets:
        assert t.resource_kind == ResourceKind.WAF_IP_SET
        assert t.scope == WafScope.REGIONAL


# ── WAF CloudFront ──────────────────────────────────────────────────────────

def _waf_cloudfront_config(*, ipv4=True, ipv6=False):
    cfg = _waf_regional_config(ipv4=ipv4, ipv6=ipv6)
    cfg["waf_scope"] = "CLOUDFRONT"
    return cfg


def test_waf_cloudfront_ipv4():
    targets = resolve_targets(_waf_cloudfront_config())
    assert len(targets) == 1
    assert targets[0].scope == WafScope.CLOUDFRONT
    assert targets[0].resource_kind == ResourceKind.WAF_IP_SET


# ── Prefix List ─────────────────────────────────────────────────────────────

def _prefix_list_config(*, ipv4=True, ipv6=False):
    return {
        "feed_name": "my-feed",
        "source_type": "HTTP",
        "source_location": "https://example.com/ips.txt",
        "parameter_path_root": "/ip-allowlist/",
        "publish_arn": "true",
        "publish_id": "true",
        "stack_name": "my-feed-sync",
        "update_role_arn": "arn:aws:iam::123456789012:role/my-feed-update-role-us-east-1",
        "waf_scope": "",
        "waf_ipv4_ipset_id": "",
        "waf_ipv4_ipset_name": "",
        "waf_ipv6_ipset_id": "",
        "waf_ipv6_ipset_name": "",
        "resource_kind": "MANAGED_PREFIX_LIST",
        "pl_ipv4_list_id": "pl-ipv4-id" if ipv4 else "",
        "pl_ipv4_list_name": "my-feed-ipv4" if ipv4 else "",
        "pl_ipv6_list_id": "pl-ipv6-id" if ipv6 else "",
        "pl_ipv6_list_name": "my-feed-ipv6" if ipv6 else "",
    }


def test_prefix_list_ipv4_only():
    targets = resolve_targets(_prefix_list_config(ipv4=True, ipv6=False))
    assert len(targets) == 1
    t = targets[0]
    assert t.resource_kind == ResourceKind.MANAGED_PREFIX_LIST
    assert t.address_family == AddressFamily.IPV4
    assert t.scope is None
    assert t.resource_id == "pl-ipv4-id"
    assert t.managed_properties == ["Entries"]


def test_prefix_list_ipv6_only():
    targets = resolve_targets(_prefix_list_config(ipv4=False, ipv6=True))
    assert len(targets) == 1
    t = targets[0]
    assert t.resource_kind == ResourceKind.MANAGED_PREFIX_LIST
    assert t.address_family == AddressFamily.IPV6
    assert t.resource_id == "pl-ipv6-id"


def test_prefix_list_dual_stack():
    targets = resolve_targets(_prefix_list_config(ipv4=True, ipv6=True))
    assert len(targets) == 2
    for t in targets:
        assert t.resource_kind == ResourceKind.MANAGED_PREFIX_LIST
        assert t.scope is None
        assert t.managed_properties == ["Entries"]


# ── Edge cases ──────────────────────────────────────────────────────────────

def test_no_address_family_enabled_raises():
    cfg = _waf_regional_config(ipv4=False, ipv6=False)
    with pytest.raises(ValueError, match="No sync targets resolved"):
        resolve_targets(cfg)


def test_no_address_family_prefix_list_raises():
    cfg = _prefix_list_config(ipv4=False, ipv6=False)
    with pytest.raises(ValueError, match="No sync targets resolved"):
        resolve_targets(cfg)


def test_unknown_waf_scope_raises():
    cfg = _waf_regional_config()
    cfg["waf_scope"] = "GLOBAL"
    with pytest.raises(ValueError, match="Unknown WAF scope"):
        resolve_targets(cfg)


def test_missing_resource_kind_and_scope_raises():
    cfg = _waf_regional_config()
    cfg["waf_scope"] = ""
    with pytest.raises(ValueError, match="Cannot determine resource kind"):
        resolve_targets(cfg)


def test_explicit_waf_resource_kind():
    cfg = _waf_regional_config()
    cfg["resource_kind"] = "WAF_IP_SET"
    targets = resolve_targets(cfg)
    assert len(targets) == 1
    assert targets[0].resource_kind == ResourceKind.WAF_IP_SET


def test_sync_target_is_immutable():
    t = SyncTarget(
        resource_id="id",
        resource_name="name",
        resource_kind=ResourceKind.WAF_IP_SET,
        address_family=AddressFamily.IPV4,
        scope=WafScope.REGIONAL,
    )
    with pytest.raises(Exception):
        t.resource_id = "other"


def test_whitespace_only_env_values_treated_as_empty():
    """Whitespace-only IDs are treated as absent, raising error if no targets."""
    cfg = _waf_regional_config(ipv4=True, ipv6=False)
    cfg["waf_ipv4_ipset_id"] = "   "
    # A whitespace-only IPv4 ID leaves no enabled targets.
    with pytest.raises(ValueError, match="No sync targets resolved"):
        resolve_targets(cfg)


def test_whitespace_id_skipped_when_other_family_enabled():
    """Whitespace-only IPv6 ID is ignored when IPv4 is valid."""
    cfg = _waf_regional_config(ipv4=True, ipv6=True)
    cfg["waf_ipv6_ipset_id"] = "   "
    targets = resolve_targets(cfg)
    assert len(targets) == 1
    assert targets[0].address_family == AddressFamily.IPV4
