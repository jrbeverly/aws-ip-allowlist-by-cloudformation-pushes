"""Tests for orchestrator.py — stack status, no-op detection, update submission."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from orchestrator import (
    OrchestratorError,
    StackState,
    UpdateRejectedError,
    _NONTERMINAL_STATES,
    get_stack_state,
    is_noop,
    is_update_blocked,
    resolve_parameter_name,
    resolve_parameter_value,
    submit_update,
)


# ── StackState ───────────────────────────────────────────────────────────────

def test_stack_state_fields():
    state = StackState(status="UPDATE_COMPLETE", parameters={"pFoo": "bar"})
    assert state.status == "UPDATE_COMPLETE"
    assert state.parameters == {"pFoo": "bar"}


def test_stack_state_immutable():
    state = StackState(status="UPDATE_COMPLETE", parameters={})
    with pytest.raises(Exception):
        state.status = "OTHER"


# ── get_stack_state ─────────────────────────────────────────────────────────

def _mock_describe_response(status, parameters=None):
    return {"Stacks": [{"StackStatus": status, "Parameters": parameters or []}]}


def test_get_stack_state_success():
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.return_value = _mock_describe_response(
        "UPDATE_COMPLETE",
        [
            {"ParameterKey": "pFeedName", "ParameterValue": "my-feed"},
            {"ParameterKey": "pIpv4Addresses", "ParameterValue": "10.0.0.0/8"},
        ],
    )

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        state = get_stack_state("my-stack")

    assert state.status == "UPDATE_COMPLETE"
    assert state.parameters == {"pFeedName": "my-feed", "pIpv4Addresses": "10.0.0.0/8"}
    mock_cfn.describe_stacks.assert_called_once_with(StackName="my-stack")


def test_get_stack_state_parameter_without_value():
    """Parameters may omit ParameterValue (e.g. for NoValue / empty defaults)."""
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.return_value = _mock_describe_response(
        "UPDATE_COMPLETE",
        [{"ParameterKey": "pIpv6Addresses"}],
    )

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        state = get_stack_state("my-stack")

    assert state.parameters == {"pIpv6Addresses": ""}


def test_get_stack_state_api_error():
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.side_effect = RuntimeError("access denied")

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        with pytest.raises(OrchestratorError, match="Failed to describe stack"):
            get_stack_state("my-stack")


def test_get_stack_state_not_found():
    mock_cfn = MagicMock()
    mock_cfn.describe_stacks.return_value = {"Stacks": []}

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        with pytest.raises(OrchestratorError, match="not found"):
            get_stack_state("unknown-stack")


# ── is_update_blocked ───────────────────────────────────────────────────────

def test_nonterminal_states_are_blocked():
    for status in _NONTERMINAL_STATES:
        assert is_update_blocked(status), f"{status} should be blocked"


def test_terminal_states_are_not_blocked():
    terminal = [
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "ROLLBACK_COMPLETE",
        "DELETE_COMPLETE",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "CREATE_FAILED",
        "DELETE_FAILED",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "ROLLBACK_FAILED",
    ]
    for status in terminal:
        assert not is_update_blocked(status), f"{status} should not be blocked"


# ── resolve_parameter_name ──────────────────────────────────────────────────

def test_param_name_waf_ipv4():
    assert resolve_parameter_name("WAF_IP_SET", "IPv4") == "pIpv4Addresses"


def test_param_name_waf_ipv6():
    assert resolve_parameter_name("WAF_IP_SET", "IPv6") == "pIpv6Addresses"


def test_param_name_pl_ipv4():
    assert resolve_parameter_name("MANAGED_PREFIX_LIST", "IPv4") == "pIpv4Entries"


def test_param_name_pl_ipv6():
    assert resolve_parameter_name("MANAGED_PREFIX_LIST", "IPv6") == "pIpv6Entries"


def test_param_name_unknown_kind_raises():
    with pytest.raises(OrchestratorError, match="Unknown resource kind"):
        resolve_parameter_name("UNKNOWN", "IPv4")


# ── resolve_parameter_value ─────────────────────────────────────────────────

def test_param_value_waf():
    mutation = {"Addresses": "10.0.0.0/8,192.168.0.0/16"}
    result = resolve_parameter_value("WAF_IP_SET", mutation)
    assert result == "10.0.0.0/8,192.168.0.0/16"


def test_param_value_waf_empty():
    result = resolve_parameter_value("WAF_IP_SET", {})
    assert result == ""


def test_param_value_pl():
    mutation = {"Entries": [{"Cidr": "10.0.0.0/8"}, {"Cidr": "192.168.0.0/16"}]}
    result = resolve_parameter_value("MANAGED_PREFIX_LIST", mutation)
    assert result == "10.0.0.0/8,192.168.0.0/16"


def test_param_value_pl_single():
    mutation = {"Entries": [{"Cidr": "::/0"}]}
    result = resolve_parameter_value("MANAGED_PREFIX_LIST", mutation)
    assert result == "::/0"


def test_param_value_pl_empty():
    result = resolve_parameter_value("MANAGED_PREFIX_LIST", {})
    assert result == ""


def test_param_value_unknown_kind_raises():
    with pytest.raises(OrchestratorError, match="Unknown resource kind"):
        resolve_parameter_value("UNKNOWN", {})


# ── is_noop ─────────────────────────────────────────────────────────────────

def test_is_noop_true_when_match():
    current = {"pIpv4Addresses": "10.0.0.0/8,192.168.0.0/16"}
    assert is_noop(current, "pIpv4Addresses", "10.0.0.0/8,192.168.0.0/16") is True


def test_is_noop_false_when_different():
    current = {"pIpv4Addresses": "10.0.0.0/8"}
    assert is_noop(current, "pIpv4Addresses", "10.0.0.0/8,192.168.0.0/16") is False


def test_is_noop_false_when_key_missing():
    current = {}
    assert is_noop(current, "pIpv4Addresses", "10.0.0.0/8") is False


def test_is_noop_false_when_key_is_none():
    current = {"pIpv4Addresses": None}
    assert is_noop(current, "pIpv4Addresses", "10.0.0.0/8") is False


# ── submit_update ───────────────────────────────────────────────────────────

def test_submit_update_success():
    mock_cfn = MagicMock()

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        submit_update(
            stack_name="my-stack",
            parameter_key="pIpv4Addresses",
            parameter_value="10.0.0.0/8,192.168.0.0/16",
            update_role_arn="arn:aws:iam::123456789012:role/update-role",
        )

    mock_cfn.update_stack.assert_called_once_with(
        StackName="my-stack",
        UsePreviousTemplate=True,
        Parameters=[
            {"ParameterKey": "pIpv4Addresses", "ParameterValue": "10.0.0.0/8,192.168.0.0/16"},
        ],
        RoleARN="arn:aws:iam::123456789012:role/update-role",
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )


def test_submit_update_rejected():
    mock_cfn = MagicMock()
    mock_cfn.update_stack.side_effect = RuntimeError("No updates are to be performed")

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        with pytest.raises(UpdateRejectedError, match="UpdateStack rejected"):
            submit_update(
                stack_name="my-stack",
                parameter_key="pIpv4Addresses",
                parameter_value="10.0.0.0/8",
                update_role_arn="arn:aws:iam::123456789012:role/update-role",
            )


def test_submit_update_pl_parameter():
    mock_cfn = MagicMock()

    with patch("orchestrator.boto3.client", return_value=mock_cfn):
        submit_update(
            stack_name="my-stack",
            parameter_key="pIpv4Entries",
            parameter_value="10.0.0.0/8,192.168.0.0/16",
            update_role_arn="arn:aws:iam::123456789012:role/update-role",
        )

    _, kwargs = mock_cfn.update_stack.call_args
    assert kwargs["Parameters"] == [
        {"ParameterKey": "pIpv4Entries", "ParameterValue": "10.0.0.0/8,192.168.0.0/16"},
    ]


# ── Exception hierarchy ─────────────────────────────────────────────────────

def test_update_rejected_is_orchestrator_error():
    assert issubclass(UpdateRejectedError, OrchestratorError)


def test_orchestrator_error_is_standard_exception():
    assert issubclass(OrchestratorError, Exception)
