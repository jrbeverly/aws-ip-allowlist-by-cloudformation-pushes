"""CloudWatch metrics and structured logging for sync observability.

Provides a MetricsRecorder that buffers metric data and flushes to
CloudWatch in batches, with automatic dimension injection for feed,
stack, and variant identity.
"""

import json
import logging
import time
from dataclasses import dataclass, field

import boto3

logger = logging.getLogger(__name__)

METRIC_NAMESPACE = "IpAllowlistSync"


@dataclass
class MetricsRecorder:
    """Buffers CloudWatch metric data and flushes in batches.

    Dimensions (FeedName, StackName, Variant) are set at construction
    and applied to every metric automatically.
    """

    feed_name: str
    stack_name: str
    variant: str

    _metrics: list[dict] = field(default_factory=list, init=False)

    def record(
        self,
        name: str,
        dimensions: dict | None = None,
        value: float = 1.0,
        unit: str = "Count",
    ) -> None:
        """Buffer a single metric data point.

        Args:
            name: CloudWatch metric name (e.g. ``FeedFetch``).
            dimensions: Per-metric dimension overrides (e.g.
                        ``{"Outcome": "Success"}``).
            value: Metric value.
            unit: CloudWatch unit (Count, Bytes, etc.).
        """
        self._metrics.append(
            {
                "MetricName": name,
                "Dimensions": [
                    {"Name": "FeedName", "Value": self.feed_name},
                    {"Name": "StackName", "Value": self.stack_name or "none"},
                    {"Name": "Variant", "Value": self.variant},
                ]
                + [
                    {"Name": k, "Value": str(v)}
                    for k, v in (dimensions or {}).items()
                ],
                "Value": value,
                "Unit": unit,
                "Timestamp": time.time(),
            }
        )

    def flush(self) -> None:
        """Push all buffered metrics to CloudWatch.

        Batches into groups of 20 (CloudWatch ``PutMetricData`` limit).
        Errors are logged but never raised — metric delivery is
        best-effort and must not block the sync cycle.
        """
        if not self._metrics:
            return
        try:
            cw = boto3.client("cloudwatch")
            for i in range(0, len(self._metrics), 20):
                batch = self._metrics[i : i + 20]
                cw.put_metric_data(
                    Namespace=METRIC_NAMESPACE,
                    MetricData=batch,
                )
        except Exception:
            logger.exception("Failed to flush CloudWatch metrics")
        finally:
            self._metrics.clear()


def resolve_variant(config: dict) -> str:
    """Derive the deployment variant string from configuration.

    Returns one of ``waf-regional``, ``waf-cloudfront``, or
    ``prefix-list-regional``.
    """
    kind = config.get("resource_kind", "")
    scope = config.get("waf_scope", "")

    if kind == "MANAGED_PREFIX_LIST":
        return "prefix-list-regional"
    if scope == "CLOUDFRONT":
        return "waf-cloudfront"
    return "waf-regional"


def log_outcome(outcome: str, **fields) -> None:
    """Emit a structured outcome log as a single JSON line.

    Args:
        outcome: Short outcome label (e.g. ``FeedFetched``,
                 ``UpdateSubmitted``).
        **fields: Arbitrary key-value context attached to the log entry.
    """
    payload = {"outcome": outcome, **fields}
    logger.info(json.dumps(payload, default=str))
