"""CloudFormation update orchestration for IP allowlist synchronization.

Checks stack status, determines whether an update is needed by comparing
current parameters against desired mutations, and submits UpdateStack
calls with the designated service role.
"""

import logging
from dataclasses import dataclass

import boto3

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Base exception for orchestration failures."""


class UpdateRejectedError(OrchestratorError):
    """UpdateStack call was rejected by CloudFormation."""


# Stack statuses that prevent submitting an update.
_NONTERMINAL_STATES = frozenset(
    {
        "CREATE_IN_PROGRESS",
        "DELETE_IN_PROGRESS",
        "IMPORT_IN_PROGRESS",
        "IMPORT_ROLLBACK_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
        "UPDATE_IN_PROGRESS",
        "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_ROLLBACK_IN_PROGRESS",
    }
)


@dataclass(frozen=True)
class StackState:
    """Snapshot of the live stack status and current parameter values."""

    status: str
    parameters: dict[str, str]


def get_stack_state(stack_name: str) -> StackState:
    """Return the current status and parameters for *stack_name*.

    Makes a single ``DescribeStacks`` call to minimise API usage.
    """
    cfn = boto3.client("cloudformation")
    try:
        response = cfn.describe_stacks(StackName=stack_name)
    except Exception as exc:
        raise OrchestratorError(
            f"Failed to describe stack {stack_name}: {exc}"
        ) from exc

    stacks = response.get("Stacks", [])
    if not stacks:
        raise OrchestratorError(f"Stack {stack_name} not found")

    stack = stacks[0]
    params = {
        p["ParameterKey"]: p.get("ParameterValue", "")
        for p in stack.get("Parameters", [])
    }
    return StackState(status=stack["StackStatus"], parameters=params)


def is_update_blocked(status: str) -> bool:
    """Return True if *status* prevents submitting a stack update."""
    return status in _NONTERMINAL_STATES


def resolve_parameter_name(resource_kind: str, address_family: str) -> str:
    """Return the CloudFormation parameter name for a managed resource.

    Args:
        resource_kind: ``WAF_IP_SET`` or ``MANAGED_PREFIX_LIST``.
        address_family: ``IPv4`` or ``IPv6``.

    Returns:
        The template parameter name (e.g. ``pIpv4Addresses``).
    """
    suffix = "4" if address_family == "IPv4" else "6"

    if resource_kind == "WAF_IP_SET":
        return f"pIpv{suffix}Addresses"

    if resource_kind == "MANAGED_PREFIX_LIST":
        return f"pIpv{suffix}Entries"

    raise OrchestratorError(
        f"Unknown resource kind {resource_kind!r}"
    )


def resolve_parameter_value(resource_kind: str, mutation: dict) -> str:
    """Extract the parameter value string from a mutation dict.

    Args:
        resource_kind: ``WAF_IP_SET`` or ``MANAGED_PREFIX_LIST``.
        mutation: Dict produced by ``generate_mutation_values``.

    Returns:
        The parameter value suitable for a CloudFormation parameter override.
    """
    if resource_kind == "WAF_IP_SET":
        return mutation.get("Addresses", "")

    if resource_kind == "MANAGED_PREFIX_LIST":
        entries = mutation.get("Entries", [])
        cidrs = [e["Cidr"] for e in entries]
        return ",".join(cidrs)

    raise OrchestratorError(
        f"Unknown resource kind {resource_kind!r}"
    )


def is_noop(current_params: dict[str, str], key: str, value: str) -> bool:
    """Return True when *key* already has *value* in *current_params*."""
    return current_params.get(key) == value


def submit_update(
    stack_name: str,
    parameter_key: str,
    parameter_value: str,
    update_role_arn: str,
    previous_keys=(),
) -> None:
    """Submit an UpdateStack request for a single parameter override.

    Uses ``UsePreviousTemplate=True`` so only the targeted parameter
    changes.  Does not wait for the update to complete.

    Raises:
        UpdateRejectedError: The UpdateStack call was rejected.
    """
    cfn = boto3.client("cloudformation")
    parameters = [
        {"ParameterKey": parameter_key, "ParameterValue": parameter_value},
    ]
    # Omitted parameters fall back to template defaults, not previous values.
    parameters += [
        {"ParameterKey": k, "UsePreviousValue": True}
        for k in previous_keys
        if k != parameter_key
    ]
    try:
        cfn.update_stack(
            StackName=stack_name,
            UsePreviousTemplate=True,
            Parameters=parameters,
            RoleARN=update_role_arn,
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
    except Exception as exc:
        raise UpdateRejectedError(
            f"UpdateStack rejected for {stack_name}: {exc}"
        ) from exc
