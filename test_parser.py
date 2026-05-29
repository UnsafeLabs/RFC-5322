#!/usr/bin/env python3
"""Tests for RFC 5322 address parser."""

import pytest
from parser import AddressParser, RFC5322Address


def test_simple_address():
    parser = AddressParser(strict=True)
    result = parser.parse("user@example.com")
    assert result.local_part == "user"
    assert result.domain == "example.com"
    assert result.display_name is None
    assert result.is_group is False


def test_angle_addr():
    parser = AddressParser(strict=True)
    result = parser.parse("<user@example.com>")
    assert result.local_part == "user"
    assert result.domain == "example.com"


def test_display_name_angle_addr():
    parser = AddressParser(strict=True)
    result = parser.parse('"John Doe" <john@example.com>')
    assert result.display_name == "John Doe"
    assert result.local_part == "john"
    assert result.domain == "example.com"


def test_display_name_no_quotes():
    parser = AddressParser(strict=True)
    result = parser.parse("John Doe <john@example.com>")
    assert result.display_name == "John Doe"
    assert result.local_part == "john"
    assert result.domain == "example.com"


def test_quoted_string_local_part():
    parser = AddressParser(strict=True)
    result = parser.parse('"user.name"@example.com')
    assert result.local_part == '"user.name"'
    assert result.domain == "example.com"


def test_domain_literal():
    parser = AddressParser(strict=True)
    result = parser.parse("user@[192.168.1.1]")
    assert result.local_part == "user"
    assert result.domain == "[192.168.1.1]"


def test_group_address():
    parser = AddressParser(strict=True)
    result = parser.parse("Managers: john@example.com, doe@example.com;")
    assert result.is_group is True
    assert result.display_name == "Managers"
    assert len(result.group_members) == 2
    assert result.group_members[0].local_part == "john"
    assert result.group_members[1].local_part == "doe"


def test_empty_group():
    parser = AddressParser(strict=True)
    result = parser.parse("Nobody:;")
    assert result.is_group is True
    assert len(result.group_members) == 0


def test_address_list():
    parser = AddressParser(strict=True)
    result = parser.parse_address_list(
        "john@example.com, \"Jane Doe\" <jane@example.com>, "
        "Admins: admin@example.com;"
    )
    assert len(result) == 3
    assert result[0].local_part == "john"
    assert result[1].display_name == "Jane Doe"
    assert result[2].is_group is True


def test_strict_rejects_obsolete():
    parser = AddressParser(strict=True)
    # Bare local part without domain — strict mode should reject
    with pytest.raises(ValueError):
        parser.parse("unquoted local-part")


def test_non_strict_accepts_obsolete():
    parser = AddressParser(strict=False)
    result = parser.parse("simple local-part")
    assert result.local_part == "simple"


def test_source_preserved():
    parser = AddressParser(strict=True)
    original = "john@example.com"
    result = parser.parse(original)
    assert result.source == original


def test_parse_mailbox_list_simple():
    parser = AddressParser(strict=True)
    result = parser.parse_mailbox_list(
        "john@example.com, jane@example.com"
    )
    assert len(result) == 2
    assert result[0].local_part == "john"
    assert result[1].local_part == "jane"


def test_parse_mailbox_list_rejects_group():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError, match="Groups are not valid"):
        parser.parse_mailbox_list("My Group: john@example.com;")


def test_parse_mailbox_list_empty():
    parser = AddressParser(strict=True)
    assert parser.parse_mailbox_list("") == []
    assert parser.parse_mailbox_list("   ") == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])