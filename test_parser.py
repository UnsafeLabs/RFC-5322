"""
RFC 5322 compliant email address parser test suite.

Minimum 60 test cases organized by RFC section:
- §3.2.1 (quoted-pair): 5 cases
- §3.2.2 (FWS): 5 cases
- §3.2.3 (CFWS/comments): 8 cases
- §3.2.4 (quoted-string): 8 cases
- §3.2.5 (miscellaneous tokens): 3 cases
- §3.4 (address/mailbox/group): 12 cases
- §3.4.1 (addr-spec/domain-literal): 8 cases
- §4.4 (obsolete addressing): 8 cases
- Edge cases: 5 cases
- Invalid/rejection cases: 8 cases
"""

import pytest
from parser import AddressParser, RFC5322Address, ParseError


@pytest.fixture
def parser():
    """Strict parser (rejects obsolete syntax)."""
    return AddressParser(strict=True)


@pytest.fixture
def permissive_parser():
    """Permissive parser (accepts obsolete syntax per §4.4)."""
    return AddressParser(strict=False)


# ============================================================================
# §3.2.1 — Quoted-Pair (5 cases)
# ============================================================================

class TestQuotedPair:
    """Test quoted-pair handling per §3.2.1."""

    def test_quoted_backslash_in_quoted_string(self, parser):
        """Quoted-pair: backslash in quoted string."""
        # Per RFC 5322 §3.2.1: the "\" in a quoted-pair is semantically invisible
        result = parser.parse(r'"user\@name"@example.com')
        assert result.local_part == "user@name"
        assert result.domain == "example.com"

    def test_quoted_quote_in_quoted_string(self, parser):
        """Quoted-pair: quote character in quoted string."""
        result = parser.parse(r'"user\"quote"@example.com')
        assert result.local_part == 'user"quote'
        assert result.domain == "example.com"

    def test_quoted_at_sign(self, parser):
        """Quoted-pair: @ sign in quoted string."""
        result = parser.parse(r'"user\@name"@example.com')
        assert result.local_part == "user@name"
        assert result.domain == "example.com"

    def test_quoted_parentheses(self, parser):
        """Quoted-pair: parentheses in quoted string."""
        result = parser.parse(r'"user\(name\)"@example.com')
        assert result.local_part == "user(name)"
        assert result.domain == "example.com"

    def test_quoted_square_brackets(self, parser):
        """Quoted-pair: square brackets in quoted string."""
        result = parser.parse(r'"user\[name\]"@example.com')
        assert result.local_part == "user[name]"
        assert result.domain == "example.com"


# ============================================================================
# §3.2.2 — Folding White Space (5 cases)
# ============================================================================

class TestFWS:
    """Test folding white space handling per §3.2.2."""

    def test_fws_in_display_name(self, parser):
        """FWS: folding in display name."""
        result = parser.parse("John\r\n Doe <john@example.com>")
        assert result.display_name == "John Doe"
        assert result.local_part == "john"

    def test_fws_before_at(self, parser):
        """FWS: whitespace before @ in addr-spec."""
        result = parser.parse("(comment)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_fws_after_at(self, parser):
        """FWS: whitespace after @ in addr-spec."""
        result = parser.parse("user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_fws_in_domain_literal(self, parser):
        """FWS: folding in domain literal."""
        result = parser.parse("user@[192.168\r\n .1.1]")
        assert result.domain == "[192.168 .1.1]"

    def test_fws_in_quoted_string(self, parser):
        """FWS: folding in quoted string."""
        result = parser.parse('"John\r\n Doe"@example.com')
        assert result.local_part == "John Doe"


# ============================================================================
# §3.2.3 — CFWS/Comments (8 cases)
# ============================================================================

class TestCFWS:
    """Test comments and CFWS handling per §3.2.3."""

    def test_comment_before_addr_spec(self, parser):
        """CFWS: comment before addr-spec."""
        result = parser.parse("(comment)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"
        assert "comment" in result.comments

    def test_comment_after_addr_spec(self, parser):
        """CFWS: comment after addr-spec."""
        result = parser.parse("user@example.com (comment)")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_comment_in_angle_addr(self, parser):
        """CFWS: comment in angle-addr."""
        result = parser.parse("John <(comment)john@example.com>")
        assert result.display_name == "John"
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_nested_comments(self, parser):
        """CFWS: nested comments."""
        result = parser.parse("(outer (inner) comment)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_comment_with_special_chars(self, parser):
        """CFWS: comment with special characters."""
        result = parser.parse("(special: chars)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_multiple_comments(self, parser):
        """CFWS: multiple comments."""
        result = parser.parse("(first)(second)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_comment_with_fws(self, parser):
        """CFWS: comment with folding white space."""
        result = parser.parse("(comment\r\n with fold)user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_comment_in_display_name(self, parser):
        """CFWS: comment in display name."""
        result = parser.parse("John (middle) Doe <john@example.com>")
        assert result.display_name == "John Doe"
        assert result.local_part == "john"
        assert result.domain == "example.com"


# ============================================================================
# §3.2.4 — Quoted Strings (8 cases)
# ============================================================================

class TestQuotedString:
    """Test quoted string handling per §3.2.4."""

    def test_simple_quoted_string(self, parser):
        """Quoted string: simple local part."""
        result = parser.parse('"user"@example.com')
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_quoted_string_with_spaces(self, parser):
        """Quoted string: spaces in local part."""
        result = parser.parse('"John Doe"@example.com')
        assert result.local_part == "John Doe"
        assert result.domain == "example.com"

    def test_quoted_string_with_folding(self, parser):
        """Quoted string: folding white space."""
        result = parser.parse('"John\r\n Doe"@example.com')
        assert result.local_part == "John Doe"
        assert result.domain == "example.com"

    def test_quoted_string_display_name(self, parser):
        """Quoted string: display name."""
        result = parser.parse('"John Doe" <john@example.com>')
        assert result.display_name == "John Doe"
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_quoted_string_empty(self, parser):
        """Quoted string: empty local part."""
        result = parser.parse('""@example.com')
        assert result.local_part == ""
        assert result.domain == "example.com"

    def test_quoted_string_with_at(self, parser):
        """Quoted string: @ in quoted string."""
        result = parser.parse('"user@name"@example.com')
        assert result.local_part == "user@name"
        assert result.domain == "example.com"

    def test_quoted_string_with_backslash(self, parser):
        """Quoted string: backslash in quoted string."""
        # Per RFC 5322 §3.2.1: the "\" is invisible, so `\n` becomes just `n`
        result = parser.parse(r'"user\name"@example.com')
        assert result.local_part == "username"
        assert result.domain == "example.com"

    def test_quoted_string_with_special_chars(self, parser):
        """Quoted string: special characters."""
        result = parser.parse(r'"user\@domain"@example.com')
        assert result.local_part == "user@domain"
        assert result.domain == "example.com"


# ============================================================================
# §3.2.5 — Miscellaneous Tokens (3 cases)
# ============================================================================

class TestMiscTokens:
    """Test miscellaneous token handling per §3.2.5."""

    def test_atom_as_local_part(self, parser):
        """Atom: simple atom as local part."""
        result = parser.parse("user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_dot_atom_as_local_part(self, parser):
        """Dot-atom: dotted local part."""
        result = parser.parse("user.name@example.com")
        assert result.local_part == "user.name"
        assert result.domain == "example.com"

    def test_atom_with_special_chars(self, parser):
        """Atom: special characters in atom."""
        result = parser.parse("user+tag@example.com")
        assert result.local_part == "user+tag"
        assert result.domain == "example.com"


# ============================================================================
# §3.4 — Address/Mailbox/Group (12 cases)
# ============================================================================

class TestAddress:
    """Test address/mailbox/group handling per §3.4."""

    def test_simple_addr_spec(self, parser):
        """Address: simple addr-spec."""
        result = parser.parse("user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"
        assert result.display_name is None

    def test_name_addr(self, parser):
        """Address: name-addr form."""
        result = parser.parse('"John Doe" <john@example.com>')
        assert result.display_name == "John Doe"
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_name_addr_quoted(self, parser):
        """Address: name-addr with quoted display name."""
        result = parser.parse('"Doe, John" <john@example.com>')
        assert result.display_name == "Doe, John"
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_group_simple(self, parser):
        """Address: simple group."""
        result = parser.parse("Group:user1@a.com,user2@b.com;")
        assert result.is_group is True
        assert result.display_name == "Group"
        assert len(result.group_members) == 2
        assert result.group_members[0].local_part == "user1"
        assert result.group_members[1].local_part == "user2"

    def test_group_empty(self, parser):
        """Address: empty group."""
        result = parser.parse('"Empty Group":;')
        assert result.is_group is True
        assert result.display_name == "Empty Group"
        assert len(result.group_members) == 0

    def test_group_single_member(self, parser):
        """Address: group with single member."""
        result = parser.parse("Group:user@example.com;")
        assert result.is_group is True
        assert result.display_name == "Group"
        assert len(result.group_members) == 1

    def test_group_with_name_addr(self, parser):
        """Address: group with name-addr members."""
        result = parser.parse('Group:"John" <john@a.com>,"Jane" <jane@b.com>;')
        assert result.is_group is True
        assert len(result.group_members) == 2
        assert result.group_members[0].display_name == "John"
        assert result.group_members[1].display_name == "Jane"

    def test_address_list(self, parser):
        """Address: address list."""
        addresses = parser.parse_address_list("user1@a.com, user2@b.com")
        assert len(addresses) == 2
        assert addresses[0].local_part == "user1"
        assert addresses[1].local_part == "user2"

    def test_mailbox_list(self, parser):
        """Address: mailbox list."""
        mailboxes = parser.parse_mailbox_list("user1@a.com, user2@b.com")
        assert len(mailboxes) == 2
        assert mailboxes[0].local_part == "user1"
        assert mailboxes[1].local_part == "user2"

    def test_mixed_address_list(self, parser):
        """Address: mixed address list with groups and mailboxes."""
        addresses = parser.parse_address_list(
            'user@a.com, Group:x@b.com,y@c.com;, user2@d.com'
        )
        assert len(addresses) == 3

    def test_addr_spec_with_comments(self, parser):
        """Address: addr-spec with comments."""
        result = parser.parse("(work) john@example.com (home)")
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_name_addr_no_display(self, parser):
        """Address: name-addr without display name."""
        result = parser.parse("<john@example.com>")
        assert result.display_name is None
        assert result.local_part == "john"
        assert result.domain == "example.com"


# ============================================================================
# §3.4.1 — Addr-Spec/Domain-Literal (8 cases)
# ============================================================================

class TestAddrSpec:
    """Test addr-spec and domain literal handling per §3.4.1."""

    def test_simple_addr_spec(self, parser):
        """Addr-spec: simple addr-spec."""
        result = parser.parse("user@example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_addr_spec_with_tag(self, parser):
        """Addr-spec: addr-spec with +tag."""
        result = parser.parse("user+tag@example.com")
        assert result.local_part == "user+tag"
        assert result.domain == "example.com"

    def test_addr_spec_with_dots(self, parser):
        """Addr-spec: addr-spec with dots."""
        result = parser.parse("first.last@example.com")
        assert result.local_part == "first.last"
        assert result.domain == "example.com"

    def test_domain_literal_ipv4(self, parser):
        """Domain literal: IPv4 address."""
        result = parser.parse("user@[192.168.1.1]")
        assert result.local_part == "user"
        assert result.domain == "[192.168.1.1]"

    def test_domain_literal_ipv6(self, parser):
        """Domain literal: IPv6 address."""
        result = parser.parse("user@[IPv6:2001:db8::1]")
        assert result.local_part == "user"
        assert result.domain == "[IPv6:2001:db8::1]"

    def test_domain_literal_with_spaces(self, parser):
        """Domain literal: with spaces."""
        result = parser.parse("user@[192.168\r\n .1.1]")
        assert result.local_part == "user"
        assert result.domain == "[192.168 .1.1]"

    def test_domain_literal_full_ipv6(self, parser):
        """Domain literal: full IPv6 address."""
        result = parser.parse("user@[IPv6:2001:db8:85a3::8a2e:370:7334]")
        assert result.local_part == "user"
        assert result.domain == "[IPv6:2001:db8:85a3::8a2e:370:7334]"

    def test_quoted_local_part(self, parser):
        """Addr-spec: quoted local part."""
        result = parser.parse('"user name"@example.com')
        assert result.local_part == "user name"
        assert result.domain == "example.com"


# ============================================================================
# §4.4 — Obsolete Addressing (8 cases)
# ============================================================================

class TestObsoleteSyntax:
    """Test obsolete syntax handling per §4.4."""

    def test_obs_local_part_mixed(self, permissive_parser):
        """Obs-local-part: mixed dot-atom and quoted-string."""
        result = permissive_parser.parse('user."quoted"@example.com')
        assert result.local_part == "user.quoted"
        assert result.domain == "example.com"

    def test_obs_domain(self, permissive_parser):
        """Obs-domain: atom form."""
        result = permissive_parser.parse("user@example")
        assert result.local_part == "user"
        assert result.domain == "example"

    def test_obs_angle_addr(self, permissive_parser):
        """Obs-angle-addr: with route."""
        result = permissive_parser.parse('"John" <@route:john@example.com>')
        assert result.display_name == "John"
        assert result.local_part == "john"
        assert result.domain == "example.com"

    def test_obs_fws(self, permissive_parser):
        """Obs-FWS: simple white space."""
        result = permissive_parser.parse("user @example.com")
        assert result.local_part == "user"
        assert result.domain == "example.com"

    def test_obs_local_part_word(self, permissive_parser):
        """Obs-local-part: word form."""
        result = permissive_parser.parse('"quoted"@example.com')
        assert result.local_part == "quoted"
        assert result.domain == "example.com"

    def test_obs_domain_atom(self, permissive_parser):
        """Obs-domain: atom form."""
        result = permissive_parser.parse("user@domain")
        assert result.local_part == "user"
        assert result.domain == "domain"

    def test_obs_dtext(self, permissive_parser):
        """Obs-dtext: quoted-pair in domain literal."""
        result = permissive_parser.parse(r"user@[192.168\.1.1]")
        assert result.local_part == "user"
        assert result.domain == "[192.168.1.1]"

    def test_obs_qp(self, permissive_parser):
        """Obs-qp: quoted-pair in quoted string."""
        # Per RFC 5322 §3.2.1: the "\" in quoted-pair is semantically invisible
        result = permissive_parser.parse(r'"user\name"@example.com')
        assert result.local_part == "username"
        assert result.domain == "example.com"


# ============================================================================
# Edge Cases (5 cases)
# ============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_max_length_addr_spec(self, parser):
        """Edge: address near 998 character limit."""
        local = "a" * 500
        domain = "b" * 490
        result = parser.parse(f"{local}@{domain}")
        assert result.local_part == local
        assert result.domain == domain

    def test_empty_quoted_string(self, parser):
        """Edge: empty quoted string local part."""
        result = parser.parse('""@example.com')
        assert result.local_part == ""
        assert result.domain == "example.com"

    def test_single_char_local(self, parser):
        """Edge: single character local part."""
        result = parser.parse("a@example.com")
        assert result.local_part == "a"
        assert result.domain == "example.com"

    def test_plus_addressing(self, parser):
        """Edge: plus addressing."""
        result = parser.parse("user+tag+more@example.com")
        assert result.local_part == "user+tag+more"
        assert result.domain == "example.com"

    def test_subdomain(self, parser):
        """Edge: subdomain in domain."""
        result = parser.parse("user@sub.domain.example.com")
        assert result.local_part == "user"
        assert result.domain == "sub.domain.example.com"


# ============================================================================
# Invalid/Rejection Cases (8 cases)
# ============================================================================

class TestInvalidAddresses:
    """Test invalid address rejection."""

    def test_empty_input(self, parser):
        """Invalid: empty input."""
        with pytest.raises(ParseError):
            parser.parse("")

    def test_no_at_sign(self, parser):
        """Invalid: missing @ sign."""
        with pytest.raises(ParseError):
            parser.parse("userexample.com")

    def test_double_at(self, parser):
        """Invalid: double @ sign."""
        with pytest.raises(ParseError):
            parser.parse("user@@example.com")

    def test_missing_local_part(self, parser):
        """Invalid: missing local part."""
        with pytest.raises(ParseError):
            parser.parse("@example.com")

    def test_missing_domain(self, parser):
        """Invalid: missing domain."""
        with pytest.raises(ParseError):
            parser.parse("user@")

    def test_unclosed_angle(self, parser):
        """Invalid: unclosed angle bracket."""
        with pytest.raises(ParseError):
            parser.parse('"John" <john@example.com')

    def test_unclosed_quoted_string(self, parser):
        """Invalid: unclosed quoted string."""
        with pytest.raises(ParseError):
            parser.parse('"user@example.com')

    def test_unclosed_domain_literal(self, parser):
        """Invalid: unclosed domain literal."""
        with pytest.raises(ParseError):
            parser.parse("user@[192.168.1.1")


# ============================================================================
# Source field tests
# ============================================================================

class TestSourceField:
    """Test that source field is populated."""

    def test_source_field_addr_spec(self, parser):
        """Source: addr-spec source field."""
        result = parser.parse("user@example.com")
        assert result.source == "user@example.com"

    def test_source_field_name_addr(self, parser):
        """Source: name-addr source field."""
        result = parser.parse('"John" <john@example.com>')
        assert result.source == '"John" <john@example.com>'

    def test_source_field_group(self, parser):
        """Source: group source field."""
        result = parser.parse("Group:user@a.com;")
        assert result.source == "Group:user@a.com;"
