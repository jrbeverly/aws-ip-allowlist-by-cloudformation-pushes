"""Tests for index.py — resource-kind reconciliation behaviour."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from discovery import AddressFamily, ResourceKind, SyncTarget, WafScope
from observability import MetricsRecorder
from orchestrator import OrchestratorError, StackState
from template import ManagedResource
from index import _match_managed_resource, _reconcile


def _make_target(kind, family, resource_id="test-id"):
    scope = WafScope.REGIONAL if kind == ResourceKind.WAF_IP_SET else None
    return SyncTarget(
        resource_id=resource_id,
        resource_name="test-resource",
        resource_kind=kind,
        address_family=family,
        scope=scope,
    )


def _make_managed_resource(kind, family, logical_id="TestResource"):
    if kind == ResourceKind.WAF_IP_SET:
        return _make_waf_managed(logical_id=logical_id)
    return ManagedResource(
        logical_id=logical_id,
        resource_type="AWS::EC2::PrefixList",
        resource_kind="MANAGED_PREFIX_LIST",
        address_family="IPv4",
        managed_properties=["Entries"],
    )


def _make_waf_managed(logical_id="WafResource", scope="REGIONAL"):
    return ManagedResource(
        logical_id=logical_id,
        resource_type="AWS::WAFv2::IPSet",
        resource_kind="WAF_IP_SET",
        address_family="IPv4",
        managed_properties=["Addresses"],
        scope=scope,
    )


def _make_config(**overrides):
    cfg = {
        "feed_name": "test-feed",
        "source_type": "HTTP",
        "source_location": "https://example.com/ips.txt",
        "parameter_path_root": "/ip-allowlist/",
        "publish_arn": "true",
        "publish_id": "true",
        "stack_name": "test-stack",
        "update_role_arn": "arn:aws:iam::123456789012:role/update-role",
        "waf_scope": "",
        "waf_ipv4_ipset_id": "",
        "waf_ipv4_ipset_name": "",
        "waf_ipv6_ipset_id": "",
        "waf_ipv6_ipset_name": "",
        "resource_kind": "",
        "pl_ipv4_list_id": "",
        "pl_ipv4_list_name": "",
        "pl_ipv6_list_id": "",
        "pl_ipv6_list_name": "",
        "pl_max_entries_ipv4": "",
        "pl_max_entries_ipv6": "",
    }
    cfg.update(overrides)
    return cfg


def _make_metrics():
    return MetricsRecorder(feed_name="test-feed", stack_name="test-stack", variant="waf-regional")


def _mock_stack_state(status="UPDATE_COMPLETE", parameters=None):
    return StackState(status=status, parameters=parameters or {})


# ── _match_managed_resource ──────────────────────────────────────────────

def test_match_by_kind_and_family():
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4)
    mr = _make_managed_resource(ResourceKind.WAF_IP_SET, AddressFamily.IPV4)
    result = _match_managed_resource(target, [mr])
    assert result is mr


def test_match_no_match_wrong_kind():
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4)
    mr = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4)
    assert _match_managed_resource(target, [mr]) is None


def test_match_no_match_wrong_family():
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV6)
    mr = _make_managed_resource(ResourceKind.WAF_IP_SET, AddressFamily.IPV4)
    assert _match_managed_resource(target, [mr]) is None


def test_match_empty_list():
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4)
    assert _match_managed_resource(target, []) is None


# ── Capacity enforcement: prefix list under capacity ─────────────────────

def _pl_under_capacity():
    """Setup: 5 CIDRs, max 100 → should proceed to update."""
    CidrCount = 5
    MaxEntries = 100
    target = _make_target(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4)
    managed = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "PrefixListIPv4")
    config = _make_config(
        resource_kind="MANAGED_PREFIX_LIST",
        pl_ipv4_list_id="pl-12345",
        pl_ipv4_list_name="test-feed-ipv4",
        pl_max_entries_ipv4=str(MaxEntries),
    )
    metrics = _make_metrics()
    cidrs = [f"10.{i}.0.0/16" for i in range(CidrCount)]
    return target, cidrs, [managed], config, metrics


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_under_capacity_proceeds_to_update(mock_state, mock_submit):
    target, cidrs, managed, config, metrics = _pl_under_capacity()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Entries": "old-value"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_called_once()
    args, _ = mock_submit.call_args
    assert args[1] == "pIpv4Entries"
    assert metrics._metrics[-1]["MetricName"] == "Reconciliation"
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_at_capacity_proceeds_to_update(mock_state, mock_submit):
    """CIDRs exactly equal to max capacity → should proceed."""
    target, cidrs, managed, config, metrics = _pl_under_capacity()
    # Use exactly MaxEntries CIDRs
    cidrs_exact = [f"10.{i}.0.0/16" for i in range(100)]
    config["pl_max_entries_ipv4"] = "100"
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Entries": "old-value"}
    )

    _reconcile(target, cidrs_exact, managed, config, metrics)

    mock_submit.assert_called_once()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


# ── Capacity enforcement: prefix list over capacity ──────────────────────

def _pl_over_capacity():
    """Setup: 150 CIDRs, max 100 → should fail capacity check."""
    CidrCount = 150
    MaxEntries = 100
    target = _make_target(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4)
    managed = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "PrefixListIPv4")
    config = _make_config(
        resource_kind="MANAGED_PREFIX_LIST",
        pl_ipv4_list_id="pl-12345",
        pl_ipv4_list_name="test-feed-ipv4",
        pl_max_entries_ipv4=str(MaxEntries),
    )
    metrics = _make_metrics()
    cidrs = [f"10.{i % 256}.{i // 256}.0/24" for i in range(CidrCount)]
    return target, cidrs, [managed], config, metrics


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_over_capacity_rejected(mock_state, mock_submit):
    target, cidrs, managed, config, metrics = _pl_over_capacity()

    _reconcile(target, cidrs, managed, config, metrics)

    mock_state.assert_not_called()
    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "ErroredCapacityExceeded"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_over_capacity_logs_outcome(mock_state, mock_submit, caplog):
    import logging
    caplog.set_level(logging.WARNING)
    target, cidrs, managed, config, metrics = _pl_over_capacity()

    _reconcile(target, cidrs, managed, config, metrics)

    assert any("capacity exceeded" in r.message for r in caplog.records)


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_over_capacity_by_one(mock_state, mock_submit):
    """101 CIDRs with max 100 → capacity exceeded."""
    target, cidrs, managed, config, metrics = _pl_over_capacity()
    cidrs_101 = [f"10.{i % 256}.{i // 256}.0/24" for i in range(101)]
    config["pl_max_entries_ipv4"] = "100"

    _reconcile(target, cidrs_101, managed, config, metrics)

    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "ErroredCapacityExceeded"


# ── Capacity enforcement: skip when not applicable ────────────────────────

@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_ipset_skips_capacity_check(mock_state, mock_submit):
    """WAF IP sets have no capacity check — many CIDRs proceed normally."""
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4, "ipset-12345")
    managed = _make_managed_resource(ResourceKind.WAF_IP_SET, AddressFamily.IPV4, "IpSetIPv4")
    config = _make_config(waf_scope="REGIONAL", waf_ipv4_ipset_id="ipset-12345")
    metrics = _make_metrics()
    cidrs = [f"10.{i % 256}.{i // 256}.0/24" for i in range(1500)]
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "old-value"}
    )

    _reconcile(target, cidrs, [managed], config, metrics)

    mock_submit.assert_called_once()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_no_max_entries_configured(mock_state, mock_submit):
    """When max entries env var is empty, capacity check is skipped."""
    target = _make_target(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "pl-12345")
    managed = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "PrefixListIPv4")
    config = _make_config(
        resource_kind="MANAGED_PREFIX_LIST",
        pl_ipv4_list_id="pl-12345",
        pl_max_entries_ipv4="",
    )
    metrics = _make_metrics()
    cidrs = [f"10.{i}.0.0/16" for i in range(200)]
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Entries": "old-value"}
    )

    _reconcile(target, cidrs, [managed], config, metrics)

    mock_submit.assert_called_once()


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_whitespace_max_entries(mock_state, mock_submit):
    """Whitespace-only max entries is treated as absent."""
    target = _make_target(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "pl-12345")
    managed = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "PrefixListIPv4")
    config = _make_config(
        resource_kind="MANAGED_PREFIX_LIST",
        pl_ipv4_list_id="pl-12345",
        pl_max_entries_ipv4="   ",
    )
    metrics = _make_metrics()
    cidrs = [f"10.{i}.0.0/16" for i in range(200)]
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Entries": "old-value"}
    )

    _reconcile(target, cidrs, [managed], config, metrics)

    mock_submit.assert_called_once()


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_pl_non_numeric_max_entries(mock_state, mock_submit):
    """Non-numeric max entries is silently ignored."""
    target = _make_target(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "pl-12345")
    managed = _make_managed_resource(ResourceKind.MANAGED_PREFIX_LIST, AddressFamily.IPV4, "PrefixListIPv4")
    config = _make_config(
        resource_kind="MANAGED_PREFIX_LIST",
        pl_ipv4_list_id="pl-12345",
        pl_max_entries_ipv4="not-a-number",
    )
    metrics = _make_metrics()
    cidrs = [f"10.{i}.0.0/16" for i in range(200)]
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Entries": "old-value"}
    )

    _reconcile(target, cidrs, [managed], config, metrics)

    mock_submit.assert_called_once()


# ── WAF Regional reconciliation ──────────────────────────────────────────


def _waf_regional_setup():
    """Setup: WAF IP_SET target + managed resource with REGIONAL scope."""
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4, "ipset-regional")
    managed = _make_waf_managed("IpSetIPv4", scope="REGIONAL")
    config = _make_config(
        waf_scope="REGIONAL",
        waf_ipv4_ipset_id="ipset-regional",
    )
    metrics = _make_metrics()
    cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
    return target, cidrs, [managed], config, metrics


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_regional_submits_correct_parameter(mock_state, mock_submit):
    """WAF regional sync submits pIpv4Addresses with comma-separated CIDRs."""
    target, cidrs, managed, config, metrics = _waf_regional_setup()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "old-value"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_called_once()
    args, _ = mock_submit.call_args
    assert args[1] == "pIpv4Addresses"
    assert args[2] == "10.0.0.0/8,192.168.0.0/16"
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_regional_noop_when_parameter_matches(mock_state, mock_submit):
    """WAF regional skips update when pIpv4Addresses already matches."""
    target, cidrs, managed, config, metrics = _waf_regional_setup()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "10.0.0.0/8,192.168.0.0/16"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "NoOp"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_regional_skip_blocked(mock_state, mock_submit):
    """WAF regional skips update when stack is in UPDATE_IN_PROGRESS."""
    target, cidrs, managed, config, metrics = _waf_regional_setup()
    mock_state.return_value = _mock_stack_state("UPDATE_IN_PROGRESS")

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "SkippedBlocked"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_regional_skip_no_match(mock_state, mock_submit):
    """WAF regional skips when no IpSync-managed resource matches."""
    target = _make_target(ResourceKind.WAF_IP_SET, AddressFamily.IPV4, "ipset-regional")
    config = _make_config(waf_scope="REGIONAL", waf_ipv4_ipset_id="ipset-regional")
    metrics = _make_metrics()
    cidrs = ["10.0.0.0/8"]

    _reconcile(target, cidrs, [], config, metrics)

    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "SkippedNoMatch"


# ── WAF CloudFront reconciliation ───────────────────────────────────────


def _waf_cloudfront_setup():
    """Setup: WAF IP_SET target + managed resource with CLOUDFRONT scope."""
    target = SyncTarget(
        resource_id="ipset-cloudfront",
        resource_name="test-feed-ipv4",
        resource_kind=ResourceKind.WAF_IP_SET,
        address_family=AddressFamily.IPV4,
        scope=WafScope.CLOUDFRONT,
    )
    managed = _make_waf_managed("IpSetIPv4", scope="CLOUDFRONT")
    config = _make_config(
        waf_scope="CLOUDFRONT",
        waf_ipv4_ipset_id="ipset-cloudfront",
    )
    metrics = MetricsRecorder(
        feed_name="test-feed",
        stack_name="test-stack",
        variant="waf-cloudfront",
    )
    cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
    return target, cidrs, [managed], config, metrics


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_cloudfront_submits_update(mock_state, mock_submit):
    """WAF CloudFront sync submits UpdateStack through metadata-driven path."""
    target, cidrs, managed, config, metrics = _waf_cloudfront_setup()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "old-value"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_called_once()
    args, _ = mock_submit.call_args
    assert args[1] == "pIpv4Addresses"
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_cloudfront_noop_when_matches(mock_state, mock_submit):
    """WAF CloudFront skips when pIpv4Addresses already matches current value."""
    target, cidrs, managed, config, metrics = _waf_cloudfront_setup()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "10.0.0.0/8,192.168.0.0/16"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    mock_submit.assert_not_called()
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "NoOp"


@patch("index.submit_update")
@patch("index.get_stack_state")
def test_waf_cloudfront_preserves_scope_in_metric(mock_state, mock_submit):
    """WAF CloudFront records the correct variant dimension on metrics."""
    target, cidrs, managed, config, metrics = _waf_cloudfront_setup()
    mock_state.return_value = _mock_stack_state(
        "UPDATE_COMPLETE", {"pIpv4Addresses": "old-value"}
    )

    _reconcile(target, cidrs, managed, config, metrics)

    assert metrics.variant == "waf-cloudfront"
    dims = {d["Name"]: d["Value"] for d in metrics._metrics[-1]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"
