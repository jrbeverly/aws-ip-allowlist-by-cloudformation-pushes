"""Tests for feed_sources.py — feed retrieval adapters."""

import io
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from feed_sources import (
    FeedSourceError,
    FetchResult,
    HttpFeedError,
    S3FeedError,
    _fetch_http,
    _fetch_s3,
    fetch_feed,
)

# ── fetch_feed (factory) ──────────────────────────────────────────────────────


def test_fetch_feed_dispatches_to_http():
    with patch("feed_sources._fetch_http") as mock_http:
        mock_http.return_value = FetchResult("data", "HTTP", "https://x")
        result = fetch_feed("HTTP", "https://example.com/ips.txt")
        mock_http.assert_called_once_with("https://example.com/ips.txt")
        assert result.content == "data"


def test_fetch_feed_dispatches_to_s3():
    with patch("feed_sources._fetch_s3") as mock_s3:
        mock_s3.return_value = FetchResult("data", "S3", "s3://b/k")
        result = fetch_feed("S3", "s3://bucket/key.txt")
        mock_s3.assert_called_once_with("s3://bucket/key.txt", None)
        assert result.content == "data"


def test_fetch_feed_source_type_case_insensitive():
    with patch("feed_sources._fetch_http") as mock_http:
        mock_http.return_value = FetchResult("x", "HTTP", "u")
        fetch_feed("http", "https://example.com/ips.txt")
        mock_http.assert_called_once()


def test_fetch_feed_unknown_source_type():
    with pytest.raises(FeedSourceError, match="Unknown source type"):
        fetch_feed("FTP", "ftp://example.com/feed.txt")


def test_fetch_feed_s3_with_bucket_override():
    with patch("feed_sources._fetch_s3") as mock_s3:
        mock_s3.return_value = FetchResult("data", "S3", "s3://b/k")
        fetch_feed("S3", "feeds/ips.txt", s3_bucket="my-bucket")
        mock_s3.assert_called_once_with("feeds/ips.txt", "my-bucket")


# ── HTTP adapter (_fetch_http) ────────────────────────────────────────────────


def test_http_success():
    mock_body = io.BytesIO(b"10.0.0.0/8\n192.168.0.0/16\n")
    mock_ctx = MagicMock()
    mock_ctx.status = 200
    mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
    mock_ctx.__exit__ = MagicMock(return_value=False)
    mock_ctx.read.return_value = mock_body.read()

    with patch("feed_sources.urlopen", return_value=mock_ctx) as mock_urlopen:
        result = _fetch_http("https://example.com/ips.txt")

    mock_urlopen.assert_called_once()
    assert result.content == "10.0.0.0/8\n192.168.0.0/16\n"
    assert result.source_type == "HTTP"
    assert result.source_location == "https://example.com/ips.txt"


def test_http_non_200_status():
    mock_ctx = MagicMock()
    mock_ctx.status = 500
    mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
    mock_ctx.__exit__ = MagicMock(return_value=False)

    with patch("feed_sources.urlopen", return_value=mock_ctx):
        with pytest.raises(HttpFeedError, match="HTTP 500"):
            _fetch_http("https://example.com/ips.txt")


def test_http_connection_error():
    from urllib.error import URLError

    with patch("feed_sources.urlopen", side_effect=URLError("connection refused")):
        with pytest.raises(HttpFeedError, match="Failed to reach"):
            _fetch_http("https://invalid.example/ips.txt")


def test_http_timeout_error():
    import socket

    with patch("feed_sources.urlopen", side_effect=TimeoutError("timed out")):
        with pytest.raises(HttpFeedError, match="Unexpected error"):
            _fetch_http("https://slow.example/ips.txt")


# ── S3 adapter (_fetch_s3) ────────────────────────────────────────────────────


def test_s3_success_from_uri():
    mock_body = MagicMock()
    mock_body.read.return_value = b"10.0.0.0/8\n"
    mock_s3 = MagicMock()
    mock_s3.get_object.return_value = {"Body": mock_body}

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        result = _fetch_s3("s3://my-bucket/feeds/ips.txt")

    mock_s3.get_object.assert_called_once_with(Bucket="my-bucket", Key="feeds/ips.txt")
    assert result.content == "10.0.0.0/8\n"
    assert result.source_type == "S3"
    assert result.source_location == "s3://my-bucket/feeds/ips.txt"


def test_s3_success_with_bucket_override():
    mock_body = MagicMock()
    mock_body.read.return_value = b"::/0\n"
    mock_s3 = MagicMock()
    mock_s3.get_object.return_value = {"Body": mock_body}

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        result = _fetch_s3("feeds/ips-v6.txt", bucket_override="my-bucket")

    mock_s3.get_object.assert_called_once_with(
        Bucket="my-bucket", Key="feeds/ips-v6.txt"
    )
    assert result.content == "::/0\n"


def test_s3_success_key_with_leading_slash():
    mock_body = MagicMock()
    mock_body.read.return_value = b"10.0.0.0/8\n"
    mock_s3 = MagicMock()
    mock_s3.get_object.return_value = {"Body": mock_body}

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        result = _fetch_s3("/feeds/ips.txt", bucket_override="my-bucket")

    mock_s3.get_object.assert_called_once_with(
        Bucket="my-bucket", Key="feeds/ips.txt"
    )
    assert result.content == "10.0.0.0/8\n"


def test_s3_invalid_uri_without_override():
    with pytest.raises(S3FeedError, match="Invalid S3 location"):
        _fetch_s3("just-a-key.txt")


def test_s3_empty_bucket_in_uri():
    with pytest.raises(S3FeedError, match="Could not determine bucket and key"):
        _fetch_s3("s3:///key-without-bucket")


def test_s3_empty_key_in_uri():
    with pytest.raises(S3FeedError, match="Could not determine bucket and key"):
        _fetch_s3("s3://bucket")


def test_s3_no_such_key():
    import botocore.exceptions

    mock_s3 = MagicMock()
    error_response = {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}}
    mock_s3.get_object.side_effect = botocore.exceptions.ClientError(
        error_response, "GetObject"
    )

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        with pytest.raises(S3FeedError, match="NoSuchKey"):
            _fetch_s3("s3://my-bucket/missing.txt")


def test_s3_access_denied():
    import botocore.exceptions

    mock_s3 = MagicMock()
    error_response = {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}}
    mock_s3.get_object.side_effect = botocore.exceptions.ClientError(
        error_response, "GetObject"
    )

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        with pytest.raises(S3FeedError, match="AccessDenied"):
            _fetch_s3("s3://private-bucket/secret.txt")


def test_s3_unexpected_exception():
    mock_s3 = MagicMock()
    mock_s3.get_object.side_effect = RuntimeError("something broke")

    with patch("feed_sources.boto3.client", return_value=mock_s3):
        with pytest.raises(S3FeedError, match="Unexpected error"):
            _fetch_s3("s3://bucket/key.txt")


# ── FetchResult ────────────────────────────────────────────────────────────────


def test_fetch_result_fields():
    result = FetchResult(content="10.0.0.0/8", source_type="HTTP", source_location="u")
    assert result.content == "10.0.0.0/8"
    assert result.source_type == "HTTP"
    assert result.source_location == "u"


def test_fetch_result_immutable():
    result = FetchResult(content="x", source_type="HTTP", source_location="u")
    with pytest.raises(Exception):
        result.content = "y"


# ── Exception hierarchy ───────────────────────────────────────────────────────


def test_exceptions_are_feed_source_errors():
    assert issubclass(HttpFeedError, FeedSourceError)
    assert issubclass(S3FeedError, FeedSourceError)


def test_feed_source_error_can_be_caught_generically():
    with patch("feed_sources._fetch_http", side_effect=HttpFeedError("boom")):
        with pytest.raises(FeedSourceError):
            fetch_feed("HTTP", "https://x")

    with patch("feed_sources._fetch_s3", side_effect=S3FeedError("boom")):
        with pytest.raises(FeedSourceError):
            fetch_feed("S3", "s3://b/k")
