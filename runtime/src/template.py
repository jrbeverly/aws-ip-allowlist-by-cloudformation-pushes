"""CloudFormation template loading and IpSync metadata-driven mutation.

Loads the current stack template body, locates synchronization-managed
resources through Metadata.IpSync, validates the contract, and produces
replacement values for the managed CIDR-bearing properties.
"""

import json
import logging
from dataclasses import dataclass
from typing import Optional

import boto3
import yaml

logger = logging.getLogger(__name__)


class TemplateError(Exception):
    """Failed to load or parse the CloudFormation template."""


class MetadataValidationError(Exception):
    """IpSync metadata on a resource is missing, malformed, or unsupported."""


@dataclass(frozen=True)
class ManagedResource:
    """A CloudFormation resource with validated IpSync metadata.

    Only resources that pass full contract validation are represented.
    Resources with invalid metadata are logged and skipped.
    """

    logical_id: str
    resource_type: str
    resource_kind: str  # "WAF_IP_SET" | "MANAGED_PREFIX_LIST"
    address_family: str  # "IPv4" | "IPv6"
    managed_properties: list[str]  # ["Addresses"] | ["Entries"]
    scope: Optional[str] = None  # "REGIONAL" | "CLOUDFRONT" (WAF only)


def load_template_body(stack_name: str) -> dict:
    """Load the current template body for *stack_name* via CloudFormation API.

    Returns the parsed template as a dict.  Handles both JSON and YAML
    template bodies returned by the ``GetTemplate`` API.
    """
    cfn = boto3.client("cloudformation")
    try:
        response = cfn.get_template(StackName=stack_name)
    except Exception as exc:
        raise TemplateError(
            f"Failed to load template for stack {stack_name}: {exc}"
        ) from exc

    body = response["TemplateBody"]
    return _parse_template_body(body)


class _CfnLoader(yaml.SafeLoader):
    pass


def _cfn_tag(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {f"Fn::{suffix}": value}


# GetTemplate returns the original YAML, including short-form intrinsics (!Ref, !Sub, ...).
_CfnLoader.add_multi_constructor("!", _cfn_tag)


def _parse_template_body(body: str) -> dict:
    """Parse a template body string, trying JSON first then YAML."""
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        pass
    try:
        return yaml.load(body, Loader=_CfnLoader)
    except yaml.YAMLError as exc:
        raise TemplateError(
            f"Failed to parse template body as JSON or YAML: {exc}"
        ) from exc


def find_managed_resources(
    template: dict,
    feed_name: str,
) -> list[ManagedResource]:
    """Find resources in *template* with valid IpSync metadata for *feed_name*.

    Resources that carry ``Metadata.IpSync`` but fail validation are
    logged with the specific contract violation and skipped.  Resources
    without ``Metadata.IpSync`` are silently ignored.

    Returns:
        List of ManagedResource records with fully validated metadata.
    """
    resources = template.get("Resources", {})
    managed: list[ManagedResource] = []

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        metadata = resource.get("Metadata")
        if not isinstance(metadata, dict):
            continue
        ip_sync = metadata.get("IpSync")
        if not isinstance(ip_sync, dict):
            continue

        try:
            mr = _validate_metadata(logical_id, ip_sync, feed_name, resource)
        except MetadataValidationError:
            logger.exception(
                "Skipping resource %s: invalid IpSync metadata", logical_id
            )
            continue

        managed.append(mr)

    return managed


def _validate_metadata(
    logical_id: str,
    ip_sync: dict,
    feed_name: str,
    resource: dict,
) -> ManagedResource:
    """Validate IpSync metadata and return a ManagedResource.

    Raises:
        MetadataValidationError: Any contract violation.
    """
    _check_version(logical_id, ip_sync)
    _check_feed_name(logical_id, ip_sync, feed_name)
    kind = _check_resource_kind(logical_id, ip_sync)
    family = _check_address_family(logical_id, ip_sync)
    managed = _check_managed_properties(logical_id, ip_sync, kind)
    scope = _check_scope(logical_id, ip_sync, kind)

    return ManagedResource(
        logical_id=logical_id,
        resource_type=resource.get("Type", ""),
        resource_kind=kind,
        address_family=family,
        managed_properties=list(managed),
        scope=scope,
    )


def _check_version(logical_id: str, ip_sync: dict) -> None:
    version = ip_sync.get("Version")
    if version != "1.0":
        raise MetadataValidationError(
            f"Resource {logical_id}: Version must be '1.0', got {version!r}"
        )


def _check_feed_name(
    logical_id: str, ip_sync: dict, feed_name: str
) -> None:
    meta_feed = ip_sync.get("FeedName")
    if meta_feed == {"Ref": "pFeedName"}:
        meta_feed = feed_name
    if not meta_feed or not isinstance(meta_feed, str):
        raise MetadataValidationError(
            f"Resource {logical_id}: FeedName is required "
            f"and must be a non-empty string"
        )
    if meta_feed != feed_name:
        raise MetadataValidationError(
            f"Resource {logical_id}: FeedName {meta_feed!r} "
            f"does not match configured feed {feed_name!r}"
        )


def _check_resource_kind(logical_id: str, ip_sync: dict) -> str:
    kind = ip_sync.get("ResourceKind")
    if kind not in ("WAF_IP_SET", "MANAGED_PREFIX_LIST"):
        raise MetadataValidationError(
            f"Resource {logical_id}: ResourceKind must be "
            f"WAF_IP_SET or MANAGED_PREFIX_LIST, got {kind!r}"
        )
    return kind


def _check_address_family(logical_id: str, ip_sync: dict) -> str:
    family = ip_sync.get("AddressFamily")
    if family not in ("IPv4", "IPv6"):
        raise MetadataValidationError(
            f"Resource {logical_id}: AddressFamily must be "
            f"IPv4 or IPv6, got {family!r}"
        )
    return family


def _check_managed_properties(
    logical_id: str, ip_sync: dict, kind: str
) -> list[str]:
    managed = ip_sync.get("ManagedProperties")
    if not managed or not isinstance(managed, list) or len(managed) == 0:
        raise MetadataValidationError(
            f"Resource {logical_id}: ManagedProperties must be "
            f"a non-empty list"
        )

    if kind == "WAF_IP_SET":
        if managed != ["Addresses"]:
            raise MetadataValidationError(
                f"Resource {logical_id}: ManagedProperties must be "
                f"['Addresses'] for WAF_IP_SET, got {managed!r}"
            )
    else:
        if managed != ["Entries"]:
            raise MetadataValidationError(
                f"Resource {logical_id}: ManagedProperties must be "
                f"['Entries'] for MANAGED_PREFIX_LIST, got {managed!r}"
            )

    return managed


def _check_scope(
    logical_id: str, ip_sync: dict, kind: str
) -> Optional[str]:
    scope = ip_sync.get("Scope")

    if kind == "WAF_IP_SET":
        if scope not in ("REGIONAL", "CLOUDFRONT"):
            raise MetadataValidationError(
                f"Resource {logical_id}: Scope must be REGIONAL "
                f"or CLOUDFRONT for WAF_IP_SET, got {scope!r}"
            )
        return scope

    # MANAGED_PREFIX_LIST must not have Scope
    if "Scope" in ip_sync:
        raise MetadataValidationError(
            f"Resource {logical_id}: Scope must not be present "
            f"on MANAGED_PREFIX_LIST"
        )
    return None


def generate_mutation_values(
    resource: ManagedResource,
    cidrs: list[str],
) -> dict:
    """Produce replacement values for *resource* from normalized CIDRs.

    Returns a dict keyed by the managed property name:

    * WAF_IP_SET → ``{"Addresses": "cidr1,cidr2,..."}``
      (comma-separated string, matching the ``pIpv{4,6}Addresses``
      parameter format)

    * MANAGED_PREFIX_LIST → ``{"Entries": [{"Cidr": "cidr1"}, ...]}``
      (list of dicts, matching the EC2 API entry shape)
    """
    if not cidrs:
        return {}

    if resource.resource_kind == "WAF_IP_SET":
        return {"Addresses": ",".join(cidrs)}
    return {"Entries": [{"Cidr": c} for c in cidrs]}
