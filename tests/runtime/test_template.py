"""Tests for template.py — template loading, metadata validation, mutation values."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../runtime/src"))

from template import (
    ManagedResource,
    MetadataValidationError,
    TemplateError,
    _parse_template_body,
    _validate_metadata,
    find_managed_resources,
    generate_mutation_values,
    load_template_body,
)

FEED = "my-feed"


# ── _parse_template_body ────────────────────────────────────────────────────

def test_parse_json_body():
    result = _parse_template_body('{"AWSTemplateFormatVersion": "2010-09-09"}')
    assert result == {"AWSTemplateFormatVersion": "2010-09-09"}


def test_parse_yaml_body():
    result = _parse_template_body("AWSTemplateFormatVersion: '2010-09-09'\n")
    assert result == {"AWSTemplateFormatVersion": "2010-09-09"}


def test_parse_unparseable_body():
    with pytest.raises(TemplateError, match="Failed to parse template body"):
        _parse_template_body("\x00\x01\x02")


# ── load_template_body (with mocked boto3) ─────────────────────────────────

def test_load_template_yaml():
    mock_cfn = MagicMock()
    mock_cfn.get_template.return_value = {
        "TemplateBody": "Description: test\n",
    }

    with patch("template.boto3.client", return_value=mock_cfn):
        result = load_template_body("my-stack")

    assert result == {"Description": "test"}
    mock_cfn.get_template.assert_called_once_with(StackName="my-stack")


def test_load_template_api_error():
    mock_cfn = MagicMock()
    mock_cfn.get_template.side_effect = RuntimeError("access denied")

    with patch("template.boto3.client", return_value=mock_cfn):
        with pytest.raises(TemplateError, match="Failed to load template"):
            load_template_body("my-stack")


# ── Helper: build a minimal template resource ──────────────────────────────

def _waf_resource(**overrides):
    meta = {
        "Version": "1.0",
        "FeedName": FEED,
        "ResourceKind": "WAF_IP_SET",
        "AddressFamily": "IPv4",
        "Scope": "REGIONAL",
        "ManagedProperties": ["Addresses"],
    }
    meta.update(overrides)
    return {
        "Type": "AWS::WAFv2::IPSet",
        "Metadata": {"IpSync": meta},
    }


def _pl_resource(**overrides):
    meta = {
        "Version": "1.0",
        "FeedName": FEED,
        "ResourceKind": "MANAGED_PREFIX_LIST",
        "AddressFamily": "IPv4",
        "ManagedProperties": ["Entries"],
    }
    meta.update(overrides)
    return {
        "Type": "AWS::EC2::PrefixList",
        "Metadata": {"IpSync": meta},
    }


def _template(*resources):
    """Build a template dict from (logical_id, resource) pairs."""
    tpl = {"AWSTemplateFormatVersion": "2010-09-09"}
    tpl["Resources"] = dict(resources)
    return tpl


# ── find_managed_resources — valid shapes ──────────────────────────────────

def test_finds_waf_resource():
    tpl = _template(("IpSetIPv4", _waf_resource()))
    result = find_managed_resources(tpl, FEED)
    assert len(result) == 1
    r = result[0]
    assert r.logical_id == "IpSetIPv4"
    assert r.resource_type == "AWS::WAFv2::IPSet"
    assert r.resource_kind == "WAF_IP_SET"
    assert r.address_family == "IPv4"
    assert r.scope == "REGIONAL"
    assert r.managed_properties == ["Addresses"]


def test_finds_pl_resource():
    tpl = _template(("PrefixListIPv4", _pl_resource()))
    result = find_managed_resources(tpl, FEED)
    assert len(result) == 1
    r = result[0]
    assert r.resource_kind == "MANAGED_PREFIX_LIST"
    assert r.scope is None
    assert r.managed_properties == ["Entries"]


def test_waf_cloudfront_scope():
    tpl = _template(("IpSetIPv4", _waf_resource(Scope="CLOUDFRONT")))
    result = find_managed_resources(tpl, FEED)
    assert result[0].scope == "CLOUDFRONT"


def test_ignores_resources_without_ip_sync():
    tpl = _template(
        ("IpSetIPv4", _waf_resource()),
        ("SomeBucket", {"Type": "AWS::S3::Bucket"}),
    )
    assert len(find_managed_resources(tpl, FEED)) == 1


def test_multiple_sync_resources():
    tpl = _template(
        ("IpSetIPv4", _waf_resource()),
        ("PrefixListIPv4", _pl_resource()),
    )
    assert len(find_managed_resources(tpl, FEED)) == 2


def test_ignores_wrong_feed_name():
    tpl = _template(("IpSetIPv4", _waf_resource(FeedName="other-feed")))
    result = find_managed_resources(tpl, FEED)
    assert len(result) == 0


def test_handles_empty_template():
    assert find_managed_resources({}, FEED) == []


def test_handles_no_resources():
    assert find_managed_resources({"Resources": {}}, FEED) == []


# ── find_managed_resources — invalid metadata is skipped ───────────────────

def test_skip_missing_version():
    tpl = _template(("R", _waf_resource(Version=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_unknown_version():
    tpl = _template(("R", _waf_resource(Version="2.0")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_missing_feed_name():
    tpl = _template(("R", _waf_resource(FeedName=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_empty_feed_name():
    tpl = _template(("R", _waf_resource(FeedName="")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_missing_resource_kind():
    tpl = _template(("R", _waf_resource(ResourceKind=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_unknown_resource_kind():
    tpl = _template(("R", _waf_resource(ResourceKind="SOMETHING_ELSE")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_missing_address_family():
    tpl = _template(("R", _waf_resource(AddressFamily=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_unknown_address_family():
    tpl = _template(("R", _waf_resource(AddressFamily="IPv5")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_missing_managed_properties():
    tpl = _template(("R", _waf_resource(ManagedProperties=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_empty_managed_properties():
    tpl = _template(("R", _waf_resource(ManagedProperties=[])))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_wrong_managed_properties_waf():
    tpl = _template(("R", _waf_resource(ManagedProperties=["Entries"])))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_wrong_managed_properties_pl():
    tpl = _template(("R", _pl_resource(ManagedProperties=["Addresses"])))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_unrecognized_managed_property_value():
    tpl = _template(("R", _waf_resource(ManagedProperties=["Addresses", "Tags"])))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_missing_scope_waf():
    tpl = _template(("R", _waf_resource(Scope=None)))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_unknown_scope():
    tpl = _template(("R", _waf_resource(Scope="GLOBAL")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_scope_on_prefix_list():
    tpl = _template(("R", _pl_resource(Scope="REGIONAL")))
    assert find_managed_resources(tpl, FEED) == []


def test_skip_metadata_not_a_dict():
    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "R": {
                "Type": "AWS::WAFv2::IPSet",
                "Metadata": "not-a-dict",
            },
        },
    }
    assert find_managed_resources(tpl, FEED) == []


def test_skip_ip_sync_not_a_dict():
    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "R": {
                "Type": "AWS::WAFv2::IPSet",
                "Metadata": {"IpSync": "not-a-dict"},
            },
        },
    }
    assert find_managed_resources(tpl, FEED) == []


def test_resource_not_a_dict_skipped():
    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "R": "not-a-dict",
        },
    }
    assert find_managed_resources(tpl, FEED) == []


# ── _validate_metadata — error messages ────────────────────────────────────

def _ip_sync(**overrides):
    base = {
        "Version": "1.0",
        "FeedName": FEED,
        "ResourceKind": "WAF_IP_SET",
        "AddressFamily": "IPv4",
        "Scope": "REGIONAL",
        "ManagedProperties": ["Addresses"],
    }
    base.update(overrides)
    return base


def _resource(**overrides):
    base = {"Type": "AWS::WAFv2::IPSet"}
    base.update(overrides)
    return base


def test_error_version_msg():
    with pytest.raises(MetadataValidationError, match="Version must be"):
        _validate_metadata("R", _ip_sync(Version="2.0"), FEED, _resource())


def test_error_feed_name_msg():
    with pytest.raises(MetadataValidationError, match="FeedName is required"):
        _validate_metadata("R", _ip_sync(FeedName=None), FEED, _resource())


def test_error_resource_kind_msg():
    with pytest.raises(MetadataValidationError, match="ResourceKind must be"):
        _validate_metadata("R", _ip_sync(ResourceKind="X"), FEED, _resource())


def test_error_address_family_msg():
    with pytest.raises(MetadataValidationError, match="AddressFamily must be"):
        _validate_metadata("R", _ip_sync(AddressFamily="X"), FEED, _resource())


def test_error_managed_properties_msg():
    with pytest.raises(
        MetadataValidationError, match="ManagedProperties must be"
    ):
        _validate_metadata("R", _ip_sync(ManagedProperties=[]), FEED, _resource())


def test_error_scope_waf_msg():
    with pytest.raises(MetadataValidationError, match="Scope must be"):
        _validate_metadata("R", _ip_sync(Scope="GLOBAL"), FEED, _resource())


def test_error_scope_on_pl_msg():
    pl = {
        "Version": "1.0",
        "FeedName": FEED,
        "ResourceKind": "MANAGED_PREFIX_LIST",
        "AddressFamily": "IPv4",
        "ManagedProperties": ["Entries"],
        "Scope": "REGIONAL",
    }
    with pytest.raises(
        MetadataValidationError, match="Scope must not be present"
    ):
        _validate_metadata("R", pl, FEED, {"Type": "AWS::EC2::PrefixList"})


# ── generate_mutation_values ───────────────────────────────────────────────

def test_mutation_waf():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::WAFv2::IPSet",
        resource_kind="WAF_IP_SET",
        address_family="IPv4",
        managed_properties=["Addresses"],
        scope="REGIONAL",
    )
    result = generate_mutation_values(r, ["10.0.0.0/8", "192.168.0.0/16"])
    assert result == {"Addresses": "10.0.0.0/8,192.168.0.0/16"}


def test_mutation_waf_single_cidr():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::WAFv2::IPSet",
        resource_kind="WAF_IP_SET",
        address_family="IPv4",
        managed_properties=["Addresses"],
        scope="REGIONAL",
    )
    result = generate_mutation_values(r, ["10.0.0.0/8"])
    assert result == {"Addresses": "10.0.0.0/8"}


def test_mutation_pl():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::EC2::PrefixList",
        resource_kind="MANAGED_PREFIX_LIST",
        address_family="IPv4",
        managed_properties=["Entries"],
    )
    result = generate_mutation_values(r, ["10.0.0.0/8", "192.168.0.0/16"])
    assert result == {
        "Entries": [{"Cidr": "10.0.0.0/8"}, {"Cidr": "192.168.0.0/16"}],
    }


def test_mutation_pl_single_cidr():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::EC2::PrefixList",
        resource_kind="MANAGED_PREFIX_LIST",
        address_family="IPv4",
        managed_properties=["Entries"],
    )
    result = generate_mutation_values(r, ["10.0.0.0/8"])
    assert result == {"Entries": [{"Cidr": "10.0.0.0/8"}]}


def test_mutation_empty_cidrs():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::WAFv2::IPSet",
        resource_kind="WAF_IP_SET",
        address_family="IPv4",
        managed_properties=["Addresses"],
        scope="REGIONAL",
    )
    assert generate_mutation_values(r, []) == {}


# ── ManagedResource ─────────────────────────────────────────────────────────

def test_managed_resource_immutable():
    r = ManagedResource(
        logical_id="R",
        resource_type="AWS::WAFv2::IPSet",
        resource_kind="WAF_IP_SET",
        address_family="IPv4",
        managed_properties=["Addresses"],
        scope="REGIONAL",
    )
    with pytest.raises(Exception):
        r.logical_id = "other"


# ── Exception hierarchy ────────────────────────────────────────────────────

def test_metadata_validation_error_is_standard_exception():
    assert issubclass(MetadataValidationError, Exception)


def test_template_error_is_standard_exception():
    assert issubclass(TemplateError, Exception)
