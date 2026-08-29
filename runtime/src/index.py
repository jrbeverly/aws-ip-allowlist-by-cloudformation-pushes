"""Lambda entry point for IP allowlist synchronization.

Invoked by EventBridge on a cron schedule defined in the owning
CloudFormation stack. Each invocation is a complete reconciliation
cycle scoped to the resources owned by this stack deployment.
"""

import logging
import os

from discovery import AddressFamily, resolve_targets
from feed_sources import FeedSourceError, fetch_feed
from normalizer import NormalizationError, normalize_ipv4
from observability import (
    MetricsRecorder,
    log_outcome,
    resolve_variant,
)
from orchestrator import (
    OrchestratorError,
    UpdateRejectedError,
    get_stack_state,
    is_noop,
    is_update_blocked,
    resolve_parameter_name,
    resolve_parameter_value,
    submit_update,
)
from template import (
    TemplateError,
    find_managed_resources,
    generate_mutation_values,
    load_template_body,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event, context):
    """Scheduled entry point for the IP allowlist synchronizer.

    Reads deployment context from environment variables, resolves
    the sync targets owned by this stack, loads the stack template
    to identify IpSync-managed resources, fetches the external feed,
    and runs reconciliation for each target.

    Metrics are buffered throughout and flushed in a ``finally``
    block so that partial signals survive unhandled exceptions.
    """
    config = _read_env()
    metrics = MetricsRecorder(
        feed_name=config["feed_name"],
        stack_name=config.get("stack_name", ""),
        variant=resolve_variant(config),
    )
    metrics.record("SyncRun", {"Outcome": "Started"})
    try:
        _run(config, metrics)
        metrics.record("SyncRun", {"Outcome": "Success"})
    except Exception:
        metrics.record("SyncRun", {"Outcome": "Failed"})
        raise
    finally:
        metrics.flush()


def _run(config, metrics):
    """Core reconciliation logic with observability signals at each phase."""
    logger.info(
        "Sync starting: feed=%s kind=%s source=%s",
        config["feed_name"],
        config.get("resource_kind") or "WAF_IP_SET",
        config["source_type"],
    )

    targets = resolve_targets(config)
    logger.info("Resolved %d sync target(s)", len(targets))
    for t in targets:
        logger.info(
            "Target: kind=%s family=%s id=%s name=%s scope=%s",
            t.resource_kind.value,
            t.address_family.value,
            t.resource_id,
            t.resource_name,
            t.scope.value if t.scope else "n/a",
        )

    stack_name = config["stack_name"]
    managed_resources: list = []
    if stack_name:
        try:
            template = load_template_body(stack_name)
        except TemplateError:
            logger.exception("Template load failed for stack %s", stack_name)
            metrics.record("TemplateLoad", {"Outcome": "Failure"})
        else:
            metrics.record("TemplateLoad", {"Outcome": "Success"})
            managed_resources = find_managed_resources(
                template, config["feed_name"]
            )
            logger.info(
                "Found %d IpSync-managed resource(s) in template",
                len(managed_resources),
            )
            for mr in managed_resources:
                logger.info(
                    "Managed resource: logical=%s kind=%s family=%s scope=%s "
                    "properties=%s",
                    mr.logical_id,
                    mr.resource_kind,
                    mr.address_family,
                    mr.scope or "n/a",
                    mr.managed_properties,
                )
    else:
        logger.warning("Stack name not configured; skipping template load")

    try:
        feed = fetch_feed(
            config["source_type"],
            config["source_location"],
        )
    except FeedSourceError:
        logger.exception(
            "Feed fetch failed: source=%s location=%s",
            config["source_type"],
            config["source_location"],
        )
        metrics.record("FeedFetch", {"Outcome": "Failure"})
        raise

    metrics.record("FeedFetch", {"Outcome": "Success"})
    logger.info("Feed fetched: type=%s bytes=%d", feed.source_type, len(feed.content))

    ipv4_targets = [t for t in targets if t.address_family == AddressFamily.IPV4]
    normalized_ipv4: list[str] = []
    if ipv4_targets:
        try:
            normalized_ipv4 = normalize_ipv4(feed.content)
        except NormalizationError:
            logger.exception(
                "IPv4 normalization failed for feed %s",
                config["feed_name"],
            )
            metrics.record("Normalization", {"Outcome": "Failure"})
            raise
        metrics.record(
            "Normalization",
            {"Outcome": "Success"},
            value=len(normalized_ipv4),
        )
        logger.info("Normalized %d IPv4 CIDR(s)", len(normalized_ipv4))

    for target in targets:
        _reconcile(target, normalized_ipv4, managed_resources, config, metrics)

    logger.info("Sync complete: feed=%s targets=%d",
                 config["feed_name"], len(targets))


def _read_env():
    """Read the full deployment context from environment variables.

    The owning CloudFormation stack injects resource identities and
    feed binding into the Lambda environment. The synchronizer does
    not scan the account for targets.
    """
    return {
        "feed_name": os.environ["IP_ALLOWLIST_FEED_NAME"],
        "source_type": os.environ["IP_ALLOWLIST_SOURCE_TYPE"],
        "source_location": os.environ["IP_ALLOWLIST_SOURCE_LOCATION"],
        "parameter_path_root": os.environ["IP_ALLOWLIST_PARAMETER_PATH_ROOT"],
        "publish_arn": os.environ.get("IP_ALLOWLIST_PUBLISH_ARN", "true"),
        "publish_id": os.environ.get("IP_ALLOWLIST_PUBLISH_ID", "true"),
        # CloudFormation stack identity
        "stack_name": os.environ.get("IP_ALLOWLIST_STACK_NAME", ""),
        "update_role_arn": os.environ.get("IP_ALLOWLIST_UPDATE_ROLE_ARN", ""),
        # WAF variant
        "waf_scope": os.environ.get("IP_ALLOWLIST_WAF_SCOPE", ""),
        "waf_ipv4_ipset_id": os.environ.get("IP_ALLOWLIST_WAF_IPV4_IPSET_ID", ""),
        "waf_ipv4_ipset_name": os.environ.get("IP_ALLOWLIST_WAF_IPV4_IPSET_NAME", ""),
        "waf_ipv6_ipset_id": os.environ.get("IP_ALLOWLIST_WAF_IPV6_IPSET_ID", ""),
        "waf_ipv6_ipset_name": os.environ.get("IP_ALLOWLIST_WAF_IPV6_IPSET_NAME", ""),
        # Prefix-list variant
        "resource_kind": os.environ.get("IP_ALLOWLIST_RESOURCE_KIND", ""),
        "pl_ipv4_list_id": os.environ.get("IP_ALLOWLIST_PL_IPV4_LIST_ID", ""),
        "pl_ipv4_list_name": os.environ.get("IP_ALLOWLIST_PL_IPV4_LIST_NAME", ""),
        "pl_ipv6_list_id": os.environ.get("IP_ALLOWLIST_PL_IPV6_LIST_ID", ""),
        "pl_ipv6_list_name": os.environ.get("IP_ALLOWLIST_PL_IPV6_LIST_NAME", ""),
        "pl_max_entries_ipv4": os.environ.get("IP_ALLOWLIST_PL_MAX_ENTRIES_IPV4", ""),
        "pl_max_entries_ipv6": os.environ.get("IP_ALLOWLIST_PL_MAX_ENTRIES_IPV6", ""),
    }


def _reconcile(target, normalized_ipv4, managed_resources, config, metrics):
    """Reconcile one target resource against the external feed.

    1. Match the target to an IpSync-managed resource in the template.
    2. Check that the owning stack is not in a nonterminal state.
    3. Produce replacement values and compare against current parameters.
    4. Submit an UpdateStack call when a real change exists.

    Each outcome is recorded as a CloudWatch metric and a structured
    JSON log line so operators can distinguish success, skip, no-op,
    and failure paths.
    """
    if target.address_family != AddressFamily.IPV4:
        logger.info(
            "Reconcile: kind=%s family=%s id=%s — IPv6 normalization not yet implemented",
            target.resource_kind.value,
            target.address_family.value,
            target.resource_id,
        )
        metrics.record("Reconciliation", {"Outcome": "SkippedIPv6"})
        log_outcome(
            "SkippedIPv6",
            kind=target.resource_kind.value,
            family=target.address_family.value,
            resource_id=target.resource_id,
        )
        return

    matched = _match_managed_resource(target, managed_resources)
    if matched is None:
        logger.info(
            "Reconcile: kind=%s family=%s id=%s — %d normalized CIDR(s) ready "
            "(no template metadata match)",
            target.resource_kind.value,
            target.address_family.value,
            target.resource_id,
            len(normalized_ipv4),
        )
        metrics.record("Reconciliation", {"Outcome": "SkippedNoMatch"})
        log_outcome(
            "SkippedNoMatch",
            kind=target.resource_kind.value,
            family=target.address_family.value,
            resource_id=target.resource_id,
            cidr_count=len(normalized_ipv4),
        )
        return

    if matched.resource_kind == "MANAGED_PREFIX_LIST":
        max_entries_raw = config.get("pl_max_entries_ipv4", "")
        if max_entries_raw and max_entries_raw.strip():
            try:
                max_entries = int(max_entries_raw.strip())
            except (ValueError, TypeError):
                max_entries = None
            else:
                if len(normalized_ipv4) > max_entries:
                    logger.warning(
                        "Reconcile: logical=%s — capacity exceeded "
                        "(%d CIDRs, max %d)",
                        matched.logical_id,
                        len(normalized_ipv4),
                        max_entries,
                    )
                    metrics.record(
                        "Reconciliation", {"Outcome": "ErroredCapacityExceeded"}
                    )
                    log_outcome(
                        "ErroredCapacityExceeded",
                        logical_id=matched.logical_id,
                        kind=matched.resource_kind,
                        family=matched.address_family,
                        cidr_count=len(normalized_ipv4),
                        max_entries=max_entries,
                    )
                    return

    mutation = generate_mutation_values(matched, normalized_ipv4)
    param_key = resolve_parameter_name(
        matched.resource_kind, matched.address_family
    )
    param_value = resolve_parameter_value(matched.resource_kind, mutation)

    stack_name = config.get("stack_name", "")
    update_role_arn = config.get("update_role_arn", "")
    if not stack_name or not update_role_arn:
        logger.warning(
            "Reconcile: logical=%s kind=%s family=%s — stack name or "
            "update role not configured; skipping update submission",
            matched.logical_id,
            matched.resource_kind,
            matched.address_family,
        )
        metrics.record("Reconciliation", {"Outcome": "SkippedNoConfig"})
        log_outcome(
            "SkippedNoConfig",
            logical_id=matched.logical_id,
            kind=matched.resource_kind,
            family=matched.address_family,
        )
        return

    try:
        state = get_stack_state(stack_name)
    except OrchestratorError:
        logger.exception(
            "Reconcile: logical=%s — failed to read stack state for %s",
            matched.logical_id,
            stack_name,
        )
        metrics.record("Reconciliation", {"Outcome": "ErroredStateRead"})
        log_outcome(
            "ErroredStateRead",
            logical_id=matched.logical_id,
            stack_name=stack_name,
        )
        return

    logger.info(
        "Reconcile: logical=%s stack=%s status=%s",
        matched.logical_id,
        stack_name,
        state.status,
    )

    if is_update_blocked(state.status):
        logger.info(
            "Reconcile: logical=%s — skipping, stack %s is in nonterminal "
            "state %s",
            matched.logical_id,
            stack_name,
            state.status,
        )
        metrics.record("Reconciliation", {"Outcome": "SkippedBlocked"})
        log_outcome(
            "SkippedBlocked",
            logical_id=matched.logical_id,
            stack_name=stack_name,
            stack_status=state.status,
        )
        return

    if is_noop(state.parameters, param_key, param_value):
        logger.info(
            "Reconcile: logical=%s — no change (%s matches current value)",
            matched.logical_id,
            param_key,
        )
        metrics.record("Reconciliation", {"Outcome": "NoOp"})
        log_outcome(
            "NoOp",
            logical_id=matched.logical_id,
            parameter_key=param_key,
        )
        return

    logger.info(
        "Reconcile: logical=%s — submitting update (%s, %d CIDR(s))",
        matched.logical_id,
        param_key,
        len(normalized_ipv4),
    )

    try:
        submit_update(stack_name, param_key, param_value, update_role_arn, state.parameters.keys())
    except UpdateRejectedError:
        logger.exception(
            "Reconcile: logical=%s — UpdateStack rejected for %s",
            matched.logical_id,
            stack_name,
        )
        metrics.record("Reconciliation", {"Outcome": "ErroredUpdateRejected"})
        log_outcome(
            "ErroredUpdateRejected",
            logical_id=matched.logical_id,
            stack_name=stack_name,
        )
        return

    logger.info(
        "Reconcile: logical=%s — UpdateStack accepted for %s",
        matched.logical_id,
        stack_name,
    )
    metrics.record("Reconciliation", {"Outcome": "Submitted"})
    log_outcome(
        "Submitted",
        logical_id=matched.logical_id,
        stack_name=stack_name,
        parameter_key=param_key,
        cidr_count=len(normalized_ipv4),
    )


def _match_managed_resource(target, managed_resources):
    """Find the template managed resource matching *target* by kind and family."""
    for mr in managed_resources:
        if mr.resource_kind == target.resource_kind.value and mr.address_family == target.address_family.value:
            return mr
    return None
