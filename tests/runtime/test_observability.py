"""Tests for observability.py — metrics recording, flushing, and variant resolution."""

import json
import logging
import os
import sys
from unittest.mock import MagicMock, call, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from observability import (
    METRIC_NAMESPACE,
    MetricsRecorder,
    log_outcome,
    resolve_variant,
)


# ── resolve_variant ──────────────────────────────────────────────────────────

def test_variant_waf_regional():
    assert resolve_variant({"waf_scope": "REGIONAL"}) == "waf-regional"


def test_variant_waf_regional_explicit_kind():
    cfg = {"waf_scope": "REGIONAL", "resource_kind": "WAF_IP_SET"}
    assert resolve_variant(cfg) == "waf-regional"


def test_variant_waf_cloudfront():
    assert resolve_variant({"waf_scope": "CLOUDFRONT"}) == "waf-cloudfront"


def test_variant_prefix_list():
    cfg = {"resource_kind": "MANAGED_PREFIX_LIST", "waf_scope": ""}
    assert resolve_variant(cfg) == "prefix-list-regional"


def test_variant_defaults_to_waf_regional():
    assert resolve_variant({}) == "waf-regional"


# ── MetricsRecorder.record ────────────────────────────────────────────────────

def _make_recorder(feed="my-feed", stack="my-stack", variant="waf-regional"):
    return MetricsRecorder(feed_name=feed, stack_name=stack, variant=variant)


def test_record_buffers_metric():
    rec = _make_recorder()
    rec.record("FeedFetch", {"Outcome": "Success"})
    assert len(rec._metrics) == 1
    m = rec._metrics[0]
    assert m["MetricName"] == "FeedFetch"
    assert m["Value"] == 1.0
    assert m["Unit"] == "Count"
    assert m["Timestamp"] > 0


def test_record_custom_value_and_unit():
    rec = _make_recorder()
    rec.record("Normalization", {"Outcome": "Success"}, value=42, unit="Count")
    assert rec._metrics[0]["Value"] == 42
    assert rec._metrics[0]["Unit"] == "Count"


def test_record_includes_feed_dimension():
    rec = _make_recorder(feed="my-feed")
    rec.record("FeedFetch", {"Outcome": "Success"})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["FeedName"] == "my-feed"


def test_record_includes_stack_dimension():
    rec = _make_recorder(stack="my-stack")
    rec.record("FeedFetch", {"Outcome": "Success"})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["StackName"] == "my-stack"


def test_record_empty_stack_becomes_none():
    rec = _make_recorder(stack="")
    rec.record("FeedFetch", {"Outcome": "Success"})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["StackName"] == "none"


def test_record_includes_variant_dimension():
    rec = _make_recorder(variant="prefix-list-regional")
    rec.record("FeedFetch", {"Outcome": "Success"})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["Variant"] == "prefix-list-regional"


def test_record_includes_per_call_dimensions():
    rec = _make_recorder()
    rec.record("Reconciliation", {"Outcome": "Submitted"})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["Outcome"] == "Submitted"


def test_record_per_call_dimension_coerced_to_string():
    rec = _make_recorder()
    rec.record("Normalization", {"CidrCount": 15})
    dims = {d["Name"]: d["Value"] for d in rec._metrics[0]["Dimensions"]}
    assert dims["CidrCount"] == "15"


def test_record_multiple_metrics():
    rec = _make_recorder()
    rec.record("FeedFetch", {"Outcome": "Success"})
    rec.record("Normalization", {"Outcome": "Success"}, value=3)
    rec.record("Reconciliation", {"Outcome": "Submitted"})
    assert len(rec._metrics) == 3
    names = [m["MetricName"] for m in rec._metrics]
    assert names == ["FeedFetch", "Normalization", "Reconciliation"]


# ── MetricsRecorder.flush ─────────────────────────────────────────────────────

def test_flush_empty_is_noop():
    rec = _make_recorder()
    with patch("observability.boto3.client") as mock_client:
        rec.flush()
    mock_client.assert_not_called()


def test_flush_sends_metrics_to_cloudwatch():
    rec = _make_recorder()
    rec.record("FeedFetch", {"Outcome": "Success"})
    rec.record("SyncRun", {"Outcome": "Started"})

    mock_cw = MagicMock()
    with patch("observability.boto3.client", return_value=mock_cw):
        rec.flush()

    mock_cw.put_metric_data.assert_called_once()
    _, kwargs = mock_cw.put_metric_data.call_args
    assert kwargs["Namespace"] == METRIC_NAMESPACE
    assert len(kwargs["MetricData"]) == 2


def test_flush_batches_large_metric_sets():
    rec = _make_recorder()
    for i in range(45):
        rec.record("Reconciliation", {"Outcome": "Submitted"})

    mock_cw = MagicMock()
    with patch("observability.boto3.client", return_value=mock_cw):
        rec.flush()

    assert mock_cw.put_metric_data.call_count == 3
    batch_sizes = [
        len(c[1]["MetricData"]) for c in mock_cw.put_metric_data.call_args_list
    ]
    assert batch_sizes == [20, 20, 5]


def test_flush_clears_buffer_after_success():
    rec = _make_recorder()
    rec.record("SyncRun", {"Outcome": "Started"})

    mock_cw = MagicMock()
    with patch("observability.boto3.client", return_value=mock_cw):
        rec.flush()

    assert len(rec._metrics) == 0


def test_flush_clears_buffer_even_on_error():
    rec = _make_recorder()
    rec.record("SyncRun", {"Outcome": "Started"})

    with patch("observability.boto3.client", side_effect=RuntimeError("boom")):
        rec.flush()

    assert len(rec._metrics) == 0


def test_flush_error_logs_and_does_not_raise():
    rec = _make_recorder()
    rec.record("SyncRun", {"Outcome": "Started"})

    with patch("observability.boto3.client", side_effect=RuntimeError("boom")):
        # Must not raise
        rec.flush()


def test_flush_dimensions_match_recorded_metric():
    rec = _make_recorder(feed="feed-a", stack="stack-b", variant="waf-cloudfront")
    rec.record("Reconciliation", {"Outcome": "Submitted"})

    mock_cw = MagicMock()
    with patch("observability.boto3.client", return_value=mock_cw):
        rec.flush()

    _, kwargs = mock_cw.put_metric_data.call_args
    m = kwargs["MetricData"][0]
    dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
    assert dims == {
        "FeedName": "feed-a",
        "StackName": "stack-b",
        "Variant": "waf-cloudfront",
        "Outcome": "Submitted",
    }


# ── log_outcome ───────────────────────────────────────────────────────────────

def test_log_outcome_emits_json_line(caplog):
    caplog.set_level(logging.INFO)
    log_outcome("FeedFetched", source="HTTP", bytes_received=1024)
    assert len(caplog.records) == 1
    parsed = json.loads(caplog.records[0].message)
    assert parsed["outcome"] == "FeedFetched"
    assert parsed["source"] == "HTTP"
    assert parsed["bytes_received"] == 1024


def test_log_outcome_no_extra_fields(caplog):
    caplog.set_level(logging.INFO)
    log_outcome("SyncStarted")
    parsed = json.loads(caplog.records[0].message)
    assert parsed == {"outcome": "SyncStarted"}
