"""Feed source adapters for retrieving external IP allowlists.

Each adapter implements a narrow fetch() contract. Source selection is
driven by the IP_ALLOWLIST_SOURCE_TYPE deployment environment variable.
No complex authentication flows are supported.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

import boto3
import botocore.exceptions


class FeedSourceError(Exception):
    """Base exception for feed retrieval failures."""


class HttpFeedError(FeedSourceError):
    """Failed to retrieve feed from an HTTPS endpoint."""


class S3FeedError(FeedSourceError):
    """Failed to retrieve feed from an S3 object."""


@dataclass(frozen=True)
class FetchResult:
    """Raw feed content returned by a source adapter."""

    content: str
    source_type: str
    source_location: str


def fetch_feed(
    source_type: str,
    source_location: str,
    s3_bucket: Optional[str] = None,
) -> FetchResult:
    """Fetch raw feed content from the configured source.

    Args:
        source_type: ``HTTP`` or ``S3`` (case-insensitive).
        source_location: URL for HTTP, ``s3://bucket/key`` URI for S3.
        s3_bucket: Optional bucket override. When provided together with
                   an S3 source type, *source_location* is treated as the
                   object key path instead of a full S3 URI.

    Returns:
        FetchResult with the raw feed content.

    Raises:
        FeedSourceError: Unknown source type or retrieval failure.
    """
    kind = source_type.strip().upper()
    if kind == "HTTP":
        return _fetch_http(source_location)
    if kind == "S3":
        return _fetch_s3(source_location, s3_bucket)
    raise FeedSourceError(
        f"Unknown source type {source_type!r}. Expected HTTP or S3."
    )


def _fetch_http(url: str) -> FetchResult:
    """Retrieve feed content from an unauthenticated HTTPS endpoint."""
    try:
        req = Request(url, headers={"User-Agent": "ip-allowlist-sync/1.0"})
        with urlopen(req, timeout=30) as response:
            if response.status != 200:
                raise HttpFeedError(f"HTTP {response.status} from {url}")
            body = response.read().decode("utf-8")
    except URLError as exc:
        raise HttpFeedError(
            f"Failed to reach {url}: {exc.reason}"
        ) from exc
    except HttpFeedError:
        raise
    except Exception as exc:
        raise HttpFeedError(
            f"Unexpected error fetching {url}: {exc}"
        ) from exc

    return FetchResult(content=body, source_type="HTTP", source_location=url)


def _fetch_s3(
    s3_uri_or_key: str,
    bucket_override: Optional[str] = None,
) -> FetchResult:
    """Retrieve feed content from an S3 object using IAM credentials.

    When *bucket_override* is provided, *s3_uri_or_key* is the object key
    within that bucket. Otherwise it must be an ``s3://bucket/key`` URI.
    """
    if bucket_override:
        bucket = bucket_override
        key = s3_uri_or_key.lstrip("/")
    elif s3_uri_or_key.startswith("s3://"):
        path = s3_uri_or_key[5:]
        parts = path.split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
    else:
        raise S3FeedError(
            f"Invalid S3 location {s3_uri_or_key!r}. "
            f"Expected s3://bucket/key or provide a bucket override."
        )

    if not bucket or not key:
        raise S3FeedError(
            f"Could not determine bucket and key from {s3_uri_or_key!r}."
        )

    try:
        s3 = boto3.client("s3")
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response["Body"].read().decode("utf-8")
    except botocore.exceptions.ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        raise S3FeedError(
            f"S3 error {code} for s3://{bucket}/{key}"
        ) from exc
    except Exception as exc:
        raise S3FeedError(
            f"Unexpected error reading s3://{bucket}/{key}: {exc}"
        ) from exc

    return FetchResult(
        content=body,
        source_type="S3",
        source_location=f"s3://{bucket}/{key}",
    )
