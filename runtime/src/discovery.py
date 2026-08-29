"""Resolve synchronization targets from deployment environment context.

Each CloudFormation deployment variant passes target resource identities
through Lambda environment variables. This module resolves those into
structured SyncTarget records without account-wide resource scanning.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ResourceKind(Enum):
    WAF_IP_SET = "WAF_IP_SET"
    MANAGED_PREFIX_LIST = "MANAGED_PREFIX_LIST"


class AddressFamily(Enum):
    IPV4 = "IPv4"
    IPV6 = "IPv6"


class WafScope(Enum):
    REGIONAL = "REGIONAL"
    CLOUDFRONT = "CLOUDFRONT"


@dataclass(frozen=True)
class SyncTarget:
    """A resource the synchronizer is responsible for keeping up to date.

    Populated from the deployment's environment variables, not from
    account-wide resource scanning.
    """

    resource_id: str
    resource_name: str
    resource_kind: ResourceKind
    address_family: AddressFamily
    scope: Optional[WafScope] = None

    @property
    def managed_properties(self) -> list[str]:
        """Properties the runtime is permitted to mutate (IpSync contract)."""
        if self.resource_kind == ResourceKind.WAF_IP_SET:
            return ["Addresses"]
        return ["Entries"]


def resolve_targets(config: dict) -> list[SyncTarget]:
    """Resolve sync targets from deployment environment variables.

    Args:
        config: Dictionary of environment variable values keyed by
                short names (e.g. ``waf_ipv4_ipset_id``).

    Returns:
        List of SyncTarget records, one per enabled address family.
    """
    kind = _resolve_resource_kind(config)
    targets: list[SyncTarget] = []

    if kind == ResourceKind.WAF_IP_SET:
        scope = _resolve_waf_scope(config)
        ipv4_id = _non_empty(config.get("waf_ipv4_ipset_id"))
        if ipv4_id:
            targets.append(SyncTarget(
                resource_id=ipv4_id,
                resource_name=config.get("waf_ipv4_ipset_name", ""),
                resource_kind=ResourceKind.WAF_IP_SET,
                address_family=AddressFamily.IPV4,
                scope=scope,
            ))
        ipv6_id = _non_empty(config.get("waf_ipv6_ipset_id"))
        if ipv6_id:
            targets.append(SyncTarget(
                resource_id=ipv6_id,
                resource_name=config.get("waf_ipv6_ipset_name", ""),
                resource_kind=ResourceKind.WAF_IP_SET,
                address_family=AddressFamily.IPV6,
                scope=scope,
            ))
    else:
        ipv4_id = _non_empty(config.get("pl_ipv4_list_id"))
        if ipv4_id:
            targets.append(SyncTarget(
                resource_id=ipv4_id,
                resource_name=config.get("pl_ipv4_list_name", ""),
                resource_kind=ResourceKind.MANAGED_PREFIX_LIST,
                address_family=AddressFamily.IPV4,
            ))
        ipv6_id = _non_empty(config.get("pl_ipv6_list_id"))
        if ipv6_id:
            targets.append(SyncTarget(
                resource_id=ipv6_id,
                resource_name=config.get("pl_ipv6_list_name", ""),
                resource_kind=ResourceKind.MANAGED_PREFIX_LIST,
                address_family=AddressFamily.IPV6,
            ))

    if not targets:
        raise ValueError(
            "No sync targets resolved. At least one address family "
            "must be enabled in the deployment configuration."
        )

    return targets


def _resolve_resource_kind(config: dict) -> ResourceKind:
    """Determine the resource kind from environment context.

    The prefix-list variant sets IP_ALLOWLIST_RESOURCE_KIND explicitly.
    WAF variants omit it, so we fall back to the presence of a WAF scope.
    """
    kind = _non_empty(config.get("resource_kind"))
    if kind == "MANAGED_PREFIX_LIST":
        return ResourceKind.MANAGED_PREFIX_LIST
    if kind == "WAF_IP_SET":
        return ResourceKind.WAF_IP_SET
    if _non_empty(config.get("waf_scope")):
        return ResourceKind.WAF_IP_SET
    raise ValueError(
        "Cannot determine resource kind from environment. "
        "Set IP_ALLOWLIST_RESOURCE_KIND or IP_ALLOWLIST_WAF_SCOPE."
    )


def _resolve_waf_scope(config: dict) -> WafScope:
    scope = _non_empty(config.get("waf_scope"))
    if scope == "REGIONAL":
        return WafScope.REGIONAL
    if scope == "CLOUDFRONT":
        return WafScope.CLOUDFRONT
    raise ValueError(
        f"Unknown WAF scope {scope!r}. Expected REGIONAL or CLOUDFRONT."
    )


def _non_empty(value: Optional[str]) -> Optional[str]:
    """Return *value* if it is a non-empty string, otherwise None."""
    if value and value.strip():
        return value.strip()
    return None
