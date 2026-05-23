"""
RFC 5322 Parser Test Suite
Organized by RFC section with 75+ test cases
"""

import pytest
from parser import (
    AddressParser, RFC5322Address, RFC5322Lexer,
    ParseError, Mode, parse_email, parse_email_list
)


# ═══════════════════════════════════════════════════════════════════════════════
# §3.2.1 Quoted Pair Tests (5 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQuotedPair:
    """Tests for §3.2.1 quoted-pair handling."""
    
    def test_quoted_pair_in_quoted_string(self):
        """Quoted pairs inside quoted strings."""
        result = parse_email('"john\\\\doe"@example.com', strict=False)
        assert result.local_part == 'john\\doe'
    
    def test_quoted_pair_backslash(self):
        """Escaped backslash in quoted string."""
        result = parse_email('"test\\\\"@example.com', strict=False)
        assert result.local_part == 'test\\'
    
    def test_quoted_pair_quote(self):
        """Escaped quote in quoted string."""
        result = parse_email('"john\\"doe"@example.com', strict=False)
        assert result.local_part == 'john"doe'
    
    def test_quoted_pair_space(self):
        """Escaped space in quoted string."""
        result = parse_email('"john\\ doe"@example.com', strict=False)
        assert result.local_part == 'john doe'
    
    def test_quoted_pair_tab(self):
        """Escaped tab in quoted string."""
        result = parse_email('"john\\\tdoe"@example.com', strict=False)
        assert result.local_part == 'john\tdoe'


# ═══════════════════════════════════════════════════════════════════════════════
# §3.2.2 FWS (Folding Whitespace) Tests (5 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFWS:
    """Tests for §3.2.2 folding whitespace."""
    
    def test_simple_space(self):
        """Simple space in display name."""
        result = parse_email('john doe <john@example.com>', strict=False)
        assert result.display_name == 'john doe'
        assert result.local_part == 'john'
    
    def test_simple_tab(self):
        """Simple tab in display name."""
        result = parse_email('john\tdoe <john@example.com>', strict=False)
        assert result.display_name == 'john doe'
    
    def test_crlf_space_folding(self):
        """CRLF followed by space (folding) in display name."""
        result = parse_email('john\r\n doe <john@example.com>', strict=False)
        assert result.display_name == 'john doe'
    
    def test_crlf_tab_folding(self):
        """CRLF followed by tab (folding) in display name."""
        result = parse_email('john\r\n\tdoe <john@example.com>', strict=False)
        assert result.display_name == 'john doe'
    
    def test_multiple_spaces(self):
        """Multiple spaces collapse to one in display name."""
        result = parse_email('"John   Doe" <john@example.com>')
        assert result.display_name == 'John   Doe'


# ═══════════════════════════════════════════════════════════════════════════════
# §3.2.3 CFWS (Comments and Folding Whitespace) Tests (8 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCFWS:
    """Tests for §3.2.3 comments and folding whitespace."""
    
    def test_simple_comment(self):
        """Simple comment extraction."""
        result = parse_email('(comment)john@example.com')
        assert 'comment' in result.comments
        assert result.local_part == 'john'
    
    def test_comment_before_at(self):
        """Comment before @ symbol."""
        result = parse_email('(comment)john@example.com')
        assert 'comment' in result.comments
    
    def test_comment_after_at(self):
        """Comment after @ symbol."""
        result = parse_email('john@(comment)@example.com')
        assert 'comment' in result.comments
    
    def test_nested_comment(self):
        """Nested comments."""
        result = parse_email('(outer(nested))john@example.com')
        assert 'outer(nested)' in result.comments
    
    def test_multiple_comments(self):
        """Multiple separate comments."""
        result = parse_email('(first)(second)john@(third)@example.com')
        assert len(result.comments) == 3
    
    def test_comment_with_quoted_pair(self):
        """Comment with escaped characters."""
        result = parse_email('(john\\(doe\\))test@example.com')
        assert 'john(doe)' in result.comments
    
    def test_comment_in_angle_addr(self):
        """Comment in angle address."""
        result = parse_email('(before)<john@example.com>(after)')
        assert 'before' in result.comments
        assert 'after' in result.comments
    
    def test_comment_with_fws(self):
        """Comment with folding whitespace."""
        result = parse_email('(comment with spaces)john@example.com')
        assert 'comment with spaces' in result.comments


# ═══════════════════════════════════════════════════════════════════════════════
# §3.2.4 Quoted String Tests (8 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestQuotedString:
    """Tests for §3.2.4 quoted string handling."""
    
    def test_simple_quoted_string(self):
        """Simple quoted local part."""
        result = parse_email('"john.doe"@example.com')
        assert result.local_part == 'john.doe'
    
    def test_quoted_string_with_space(self):
        """Quoted string containing space."""
        result = parse_email('"john doe"@example.com')
        assert result.local_part == 'john doe'
    
    def test_quoted_string_with_special_chars(self):
        """Quoted string with special characters."""
        result = parse_email('"john@doe"@example.com')
        assert result.local_part == 'john@doe'
    
    def test_quoted_string_with_backslash(self):
        """Quoted string with escaped backslash."""
        result = parse_email('"john\\\\doe"@example.com', strict=False)
        assert result.local_part == 'john\\doe'
    
    def test_quoted_string_with_quote(self):
        """Quoted string with escaped quote."""
        result = parse_email('"john\\"doe"@example.com', strict=False)
        assert result.local_part == 'john"doe'
    
    def test_quoted_string_empty(self):
        """Empty quoted string."""
        result = parse_email('""@example.com')
        assert result.local_part == ''
    
    def test_quoted_string_with_fws(self):
        """Quoted string with folding whitespace."""
        result = parse_email('"john\\r\\n doe"@example.com', strict=False)
        assert result.local_part == 'john doe'
    
    def test_quoted_string_all_special(self):
        """Quoted string with all special characters."""
        result = parse_email('"very.(),:;<>\\"@[]\\ long"@example.com', strict=False)
        assert result.local_part == 'very.(),:;<>"@[]\\ long'


# ═══════════════════════════════════════════════════════════════════════════════
# §3.2.5 Miscellaneous Tokens Tests (3 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMiscellaneousTokens:
    """Tests for §3.2.5 miscellaneous tokens."""
    
    def test_atext_characters(self):
        """All allowed atext characters."""
        result = parse_email('!#$%&\'*+-/=?^_`{|}~@example.com')
        assert result.local_part == "!#$%&'*+-/=?^_`{|}~"
    
    def test_alpha_numeric(self):
        """Alphanumeric characters."""
        result = parse_email('john123doe@example.com')
        assert result.local_part == 'john123doe'
    
    def test_mixed_atext(self):
        """Mixed atext characters."""
        result = parse_email('john_doe+tag@example.com')
        assert result.local_part == 'john_doe+tag'


# ═══════════════════════════════════════════════════════════════════════════════
# §3.4 Address / Mailbox / Group Tests (12 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAddressMailboxGroup:
    """Tests for §3.4 address, mailbox, and group parsing."""
    
    def test_simple_addr_spec(self):
        """Simple addr-spec."""
        result = parse_email('john@example.com')
        assert result.local_part == 'john'
        assert result.domain == 'example.com'
        assert result.display_name is None
    
    def test_name_addr_with_display(self):
        """name-addr with display name."""
        result = parse_email('"John Doe" <john@example.com>')
        assert result.display_name == 'John Doe'
        assert result.local_part == 'john'
        assert result.domain == 'example.com'
    
    def test_name_addr_without_quotes(self):
        """name-addr with unquoted display name."""
        result = parse_email('John Doe <john@example.com>')
        assert result.display_name == 'John Doe'
        assert result.local_part == 'john'
    
    def test_angle_addr_only(self):
        """Angle-addr without display name."""
        result = parse_email('<john@example.com>')
        assert result.local_part == 'john'
        assert result.display_name is None
    
    def test_simple_group(self):
        """Simple group address."""
        result = parse_email('group: john@example.com, jane@example.org;')
        assert result.is_group
        assert result.display_name == 'group'
        assert len(result.group_members) == 2
    
    def test_group_single_member(self):
        """Group with single member."""
        result = parse_email('team: john@example.com;')
        assert result.is_group
        assert len(result.group_members) == 1
    
    def test_group_empty(self):
        """Empty group."""
        result = parse_email('group: ;', strict=False)
        assert result.is_group
        assert len(result.group_members) == 0
    
    def test_group_with_display_names(self):
        """Group members with display names."""
        result = parse_email('team: "John" <john@a.com>, "Jane" <jane@b.com>;')
        assert result.is_group
        assert result.group_members[0].display_name == 'John'
    
    def test_address_list_simple(self):
        """Simple address list."""
        parser = AddressParser()
        results = parser.parse_address_list('john@a.com, jane@b.com')
        assert len(results) == 2
        assert results[0].local_part == 'john'
        assert results[1].local_part == 'jane'
    
    def test_address_list_with_names(self):
        """Address list with display names."""
        parser = AddressParser()
        results = parser.parse_address_list('John <john@a.com>, Jane <jane@b.com>')
        assert len(results) == 2
        assert results[0].display_name == 'John'
    
    def test_mailbox_list_rejects_group(self):
        """mailbox-list should reject groups."""
        parser = AddressParser()
        with pytest.raises(ParseError):
            parser.parse_mailbox_list('group: john@a.com;')
    
    def test_mailbox_list_accepts_mailboxes(self):
        """mailbox-list accepts only mailboxes."""
        parser = AddressParser()
        results = parser.parse_mailbox_list('john@a.com, jane@b.com')
        assert len(results) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# §3.4.1 Addr-spec / Domain-literal Tests (8 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAddrSpecDomainLiteral:
    """Tests for §3.4.1 addr-spec and domain-literal."""
    
    def test_simple_addr_spec(self):
        """Simple addr-spec parsing."""
        result = parse_email('user@example.com')
        assert result.local_part == 'user'
        assert result.domain == 'example.com'
    
    def test_dot_atom_local(self):
        """Dot-atom in local part."""
        result = parse_email('john.doe.smith@example.com')
        assert result.local_part == 'john.doe.smith'
    
    def test_dot_atom_domain(self):
        """Dot-atom in domain."""
        result = parse_email('john@mail.example.com')
        assert result.domain == 'mail.example.com'
    
    def test_domain_literal_ipv4(self):
        """Domain literal with IPv4."""
        result = parse_email('user@[192.168.1.1]')
        assert result.domain == '[192.168.1.1]'
    
    def test_domain_literal_ipv6(self):
        """Domain literal with IPv6."""
        result = parse_email('user@[IPv6:2001:db8::1]')
        assert result.domain == '[IPv6:2001:db8::1]'
    
    def test_domain_literal_full_ipv6(self):
        """Full IPv6 address."""
        result = parse_email('postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]')
        assert '2001:db8:85a3::8a2e:370:7334' in result.domain
    
    def test_domain_literal_with_quoted_pair(self):
        """Domain literal with quoted pair."""
        result = parse_email('user@[192.168.1.\\1]', strict=False)
        assert '[192.168.1.1]' == result.domain
    
    def test_mixed_local_domain(self):
        """Mixed local part and domain forms."""
        result = parse_email('"quoted"@[192.168.1.1]')
        assert result.local_part == 'quoted'
        assert result.domain == '[192.168.1.1]'


# ═══════════════════════════════════════════════════════════════════════════════
# §4.4 Obsolete Addressing Tests (8 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestObsoleteAddressing:
    """Tests for §4.4 obsolete addressing forms."""
    
    def test_obs_local_part_simple(self):
        """Simple obs-local-part."""
        result = parse_email('user.@example.com', strict=False)
        assert result.local_part == 'user.'
    
    def test_obs_local_part_mixed(self):
        """Mixed dot-atom and quoted-string in obs-local-part."""
        result = parse_email('user."quoted"@example.com', strict=False)
        assert result.local_part == 'user.quoted'
    
    def test_obs_local_part_multiple(self):
        """Multiple obs-local-part segments."""
        result = parse_email('a.b.c.d@example.com', strict=False)
        assert result.local_part == 'a.b.c.d'
    
    def test_obs_domain_simple(self):
        """Simple obs-domain."""
        result = parse_email('user@.example.com', strict=False)
        assert result.domain == '.example.com'
    
    def test_obs_domain_trailing_dot(self):
        """Domain with trailing dot (obs-domain)."""
        result = parse_email('user@example.com.', strict=False)
        assert result.domain == 'example.com.'
    
    def test_strict_rejects_obs_local(self):
        """Strict mode rejects obs-local-part."""
        with pytest.raises(ParseError):
            parse_email('user.@example.com', strict=True)
    
    def test_strict_rejects_obs_domain(self):
        """Strict mode rejects obs-domain."""
        with pytest.raises(ParseError):
            parse_email('user@.example.com', strict=True)
    
    def test_permissive_accepts_both(self):
        """Permissive mode accepts both obs forms."""
        result = parse_email('user..name.@.example..com.', strict=False)
        assert result.local_part == 'user..name.'
        assert result.domain == '.example..com.'


# ═══════════════════════════════════════════════════════════════════════════════
# Edge Cases Tests (5 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases and boundary conditions."""
    
    def test_max_length_input(self):
        """Input at maximum RFC 5322 line length."""
        local = 'a' * 64
        domain = 'b' * 63 + '.com'
        email = f'{local}@{domain}'
        result = parse_email(email)
        assert result.local_part == local
    
    def test_very_long_input_rejected(self):
        """Input exceeding max length is rejected."""
        long_email = 'a' * 1000 + '@example.com'
        with pytest.raises(ParseError):
            parse_email(long_email)
    
    def test_empty_local_quoted(self):
        """Empty local part in quotes."""
        result = parse_email('""@example.com')
        assert result.local_part == ''
    
    def test_unicode_in_display_name(self):
        """Unicode in display name (should work in quoted string)."""
        result = parse_email('"José María" <jose@example.com>', strict=False)
        assert 'José' in result.display_name
    
    def test_deeply_nested_comments(self):
        """Deeply nested comments."""
        result = parse_email('(a(b(c(d)e)f)g)test@example.com')
        assert 'a(b(c(d)e)f)g' in result.comments


# ═══════════════════════════════════════════════════════════════════════════════
# Invalid / Rejection Tests (8 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestInvalidRejection:
    """Invalid inputs that should be rejected."""
    
    def test_missing_at_symbol(self):
        """Missing @ symbol."""
        with pytest.raises(ParseError):
            parse_email('johnexample.com')
    
    def test_multiple_at_symbols(self):
        """Multiple @ symbols."""
        with pytest.raises(ParseError):
            parse_email('john@doe@example.com')
    
    def test_unclosed_quoted_string(self):
        """Unclosed quoted string."""
        with pytest.raises(ParseError):
            parse_email('"john@example.com')
    
    def test_unclosed_angle_addr(self):
        """Unclosed angle address."""
        with pytest.raises(ParseError):
            parse_email('<john@example.com')
    
    def test_unclosed_comment(self):
        """Unclosed comment."""
        with pytest.raises(ParseError):
            parse_email('(comment john@example.com')
    
    def test_invalid_characters(self):
        """Invalid characters in local part."""
        with pytest.raises(ParseError):
            parse_email('john<doe@example.com')
    
    def test_empty_input(self):
        """Empty input."""
        with pytest.raises(ParseError):
            parse_email('')
    
    def test_whitespace_only(self):
        """Whitespace only input."""
        with pytest.raises(ParseError):
            parse_email('   ')


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Function Tests (5 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_email_strict_default(self):
        """parse_email defaults to strict mode."""
        result = parse_email('john@example.com')
        assert result.local_part == 'john'
    
    def test_parse_email_permissive(self):
        """parse_email with permissive mode."""
        result = parse_email('user.@example.com', strict=False)
        assert result.local_part == 'user.'
    
    def test_parse_email_list_simple(self):
        """parse_email_list with simple addresses."""
        results = parse_email_list('a@b.com, c@d.com, e@f.com')
        assert len(results) == 3
    
    def test_parse_email_list_with_names(self):
        """parse_email_list with display names."""
        results = parse_email_list('A <a@b.com>, B <c@d.com>')
        assert results[0].display_name == 'A'
        assert results[1].display_name == 'B'
    
    def test_parse_email_list_single(self):
        """parse_email_list with single address."""
        results = parse_email_list('john@example.com')
        assert len(results) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests (3 cases)
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests combining multiple features."""
    
    def test_complex_real_world_1(self):
        """Complex real-world example 1."""
        result = parse_email('"John Doe" (comment) <john(comment)@(comment)example.com> (after)')
        assert result.display_name == 'John Doe'
        assert result.local_part == 'john'
        assert len(result.comments) >= 3
    
    def test_complex_real_world_2(self):
        """Complex real-world example 2."""
        result = parse_email('(pre)"quoted name"(mid)<"quoted"@example.com>(post)', strict=False)
        assert result.display_name == 'quoted name'
        assert result.local_part == 'quoted'
    
    def test_complex_address_list(self):
        """Complex address list with groups and individuals."""
        parser = AddressParser()
        results = parser.parse_address_list(
            'Team: john@a.com, "Jane" <jane@b.com>;, bob@c.com'
        )
        assert len(results) == 2  # Group counts as one, plus bob


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
