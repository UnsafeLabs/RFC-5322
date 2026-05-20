"""
Comprehensive test suite for the RFC 5322 email address parser.

Organized by RFC section, with 60+ test cases covering:
- §3.2.1 quoted-pair (5 cases)
- §3.2.2 FWS (5 cases)
- §3.2.3 CFWS / comments (8 cases)
- §3.2.4 quoted-string (8 cases)
- §3.2.5 miscellaneous tokens (3 cases)
- §3.4 address/mailbox/group (12 cases)
- §3.4.1 addr-spec / domain-literal (8 cases)
- §4.4 obsolete addressing (8 cases)
- Edge cases (5+ cases)
- Invalid/rejection cases (8+ cases)
"""

import pytest
from parser import AddressParser, RFC5322Address


# ── §3.2.1 Quoted-Pair (5+ cases) ────────────────────────────────────────────

class TestQuotedPair:
    """§3.2.1: quoted-pair = ("\" (VCHAR / WSP)) / obs-qp"""

    def test_backslash_escaped_at_sign(self):
        p = AddressParser(strict=True)
        r = p.parse('"test\\@inside"@example.com')
        assert r.local_part == 'test@inside'
        assert r.domain == 'example.com'

    def test_backslash_escaped_quote(self):
        p = AddressParser(strict=True)
        r = p.parse('"test\\"inside"@example.com')
        assert r.local_part == 'test"inside'

    def test_backslash_escaped_backslash(self):
        p = AddressParser(strict=True)
        r = p.parse('"test\\\\inside"@example.com')
        assert r.local_part == 'test\\inside'

    def test_backslash_in_comment(self):
        p = AddressParser(strict=True)
        r = p.parse('(comment\\ with\\ backslash)user@example.com')
        assert r.local_part == 'user'
        assert any('backslash' in c for c in r.comments)

    def test_invalid_quoted_pair_strict(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('"\\\x01invalid"@example.com')


# ── §3.2.2 FWS (5+ cases) ────────────────────────────────────────────────────

class TestFoldingWhitespace:
    """§3.2.2: FWS = ([*WSP CRLF] 1*WSP) / obs-FWS"""

    def test_fws_after_at_sign_strict(self):
        p = AddressParser(strict=True)
        r = p.parse('user@ example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_fws_before_at_strict(self):
        p = AddressParser(strict=True)
        r = p.parse('user @example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_fws_in_display_name(self):
        p = AddressParser(strict=True)
        r = p.parse('John  Doe <john@example.com>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'john'

    def test_tab_as_fws(self):
        p = AddressParser(strict=True)
        r = p.parse('user@\texample.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_fws_between_mailboxes(self):
        p = AddressParser(strict=True)
        addrs = p.parse_address_list('a@b.com,  c@d.com')
        assert len(addrs) == 2
        assert addrs[1].local_part == 'c'
        assert addrs[1].domain == 'd.com'


# ── §3.2.3 CFWS / Comments (8+ cases) ────────────────────────────────────────

class TestCommentsAndCFWS:
    """§3.2.3: CFWS = (1*([FWS] comment) [FWS]) / FWS"""

    def test_simple_comment_before_local_part(self):
        p = AddressParser(strict=True)
        r = p.parse('(hello)user@example.com')
        assert r.local_part == 'user'
        assert 'hello' in r.comments

    def test_comment_after_domain(self):
        p = AddressParser(strict=True)
        r = p.parse('user@example.com(bye)')
        assert r.domain == 'example.com'
        assert any('bye' in c for c in r.comments)

    def test_mid_comment(self):
        # CFWS between two atoms without a dot is NOT a valid dot-atom
        # in strict mode. The comment splits the atom, making it two
        # separate atoms = phrase, not addr-spec. Invalid in strict mode.
        # Also invalid in permissive mode because obs-local-part
        # requires dots between words (§4.4: word *("." word)).
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('user(middle)name@example.com')
        p2 = AddressParser(strict=False)
        with pytest.raises(ValueError):
            p2.parse('user(middle)name@example.com')

    def test_nested_comments(self):
        p = AddressParser(strict=True)
        r = p.parse('(outer(inner)back)user@example.com')
        assert r.local_part == 'user'
        assert any('inner' in c for c in r.comments) or any('outer' in c for c in r.comments)

    def test_comment_in_display_name(self):
        p = AddressParser(strict=True)
        r = p.parse('(note)John Doe <john@example.com>')
        assert r.display_name == 'John Doe'
        assert 'note' in r.comments

    def test_comment_in_group(self):
        p = AddressParser(strict=True)
        r = p.parse('My Group(comment):user@a.com;')
        assert r.is_group
        assert r.display_name == 'My Group'

    def test_comment_around_angle_addr(self):
        p = AddressParser(strict=True)
        r = p.parse('(before)<user@example.com>(after)')
        assert r.local_part == 'user'
        assert any('before' in c for c in r.comments)
        assert any('after' in c for c in r.comments)

    def test_multiple_comments(self):
        p = AddressParser(strict=True)
        r = p.parse('(one)(two)user(three)@example.com(four)')
        assert r.local_part == 'user'
        assert len(r.comments) >= 3


# ── §3.2.4 Quoted-String (8+ cases) ──────────────────────────────────────────

class TestQuotedString:
    """§3.2.4: quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]"""

    def test_basic_quoted_string_local_part(self):
        p = AddressParser(strict=True)
        r = p.parse('"hello world"@example.com')
        assert r.local_part == 'hello world'

    def test_space_only_quoted_string(self):
        p = AddressParser(strict=True)
        r = p.parse('" "@example.com')
        assert r.domain == 'example.com'

    def test_quoted_string_with_special_chars(self):
        p = AddressParser(strict=True)
        # \\\\ -> \\ -> the quoted-pair escapes a backslash
        # result should include one backslash
        r = p.parse('"very.(),:;<>[]\\\\ long"@example.com')
        assert r.local_part == 'very.(),:;<>[]\\ long'

    def test_quoted_string_display_name(self):
        p = AddressParser(strict=True)
        r = p.parse('"John Doe" <john@example.com>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'john'

    def test_quoted_string_with_escaped_quote(self):
        p = AddressParser(strict=True)
        r = p.parse('"escaped\\"quote"@example.com')
        assert r.local_part == 'escaped"quote'

    def test_quoted_string_in_mixed_local_part(self):
        p = AddressParser(strict=False)
        r = p.parse('first."middle part"@example.com')
        assert r.local_part == 'first."middle part"'

    def test_empty_quoted_string(self):
        p = AddressParser(strict=True)
        r = p.parse('""@example.com')
        assert r.local_part == ''

    def test_quoted_string_with_hex_chars(self):
        p = AddressParser(strict=True)
        r = p.parse('"test\\x20space"@example.com')
        # x is a valid VCHAR in a quoted-pair
        assert r.local_part == 'testx20space'


# ── §3.2.5 Miscellaneous Tokens (3+ cases) ───────────────────────────────────

class TestMiscTokens:
    """§3.2.5: atext, atom, dot-atom, specials"""

    def test_dot_atom_local_part(self):
        p = AddressParser(strict=True)
        r = p.parse('first.last@example.com')
        assert r.local_part == 'first.last'

    def test_dot_atom_domain(self):
        p = AddressParser(strict=True)
        r = p.parse('user@mail.example.com')
        assert r.domain == 'mail.example.com'

    def test_atom_with_allowed_specials(self):
        p = AddressParser(strict=True)
        r = p.parse('user+tag_sub!123@example.com')
        assert r.local_part == 'user+tag_sub!123'


# ── §3.4 Address / Mailbox / Group (12+ cases) ───────────────────────────────

class TestAddressMailboxGroup:
    """§3.4: address, mailbox, group, address-list, mailbox-list"""

    def test_simple_addr_spec(self):
        p = AddressParser(strict=True)
        r = p.parse('user@example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'
        assert not r.is_group
        assert r.display_name is None

    def test_name_addr_with_display_name(self):
        p = AddressParser(strict=True)
        r = p.parse('John Smith <john@example.com>')
        assert r.display_name == 'John Smith'
        assert r.local_part == 'john'
        assert r.domain == 'example.com'

    def test_angle_addr_no_display(self):
        p = AddressParser(strict=True)
        r = p.parse('<user@example.com>')
        assert r.display_name is None
        assert r.local_part == 'user'

    def test_group_address(self):
        p = AddressParser(strict=True)
        r = p.parse('Recipients:alice@a.com, bob@b.com;')
        assert r.is_group
        assert r.display_name == 'Recipients'
        assert len(r.group_members) == 2
        assert r.group_members[0].local_part == 'alice'
        assert r.group_members[1].local_part == 'bob'

    def test_empty_group(self):
        p = AddressParser(strict=True)
        r = p.parse('Empty Group:;')
        assert r.is_group
        assert r.display_name == 'Empty Group'
        assert len(r.group_members) == 0

    def test_group_with_single_member(self):
        p = AddressParser(strict=True)
        r = p.parse('Solo:user@domain.com;')
        assert r.is_group
        assert len(r.group_members) == 1

    def test_address_list_two(self):
        p = AddressParser(strict=True)
        addrs = p.parse_address_list('alice@a.com, bob@b.com')
        assert len(addrs) == 2
        assert addrs[0].local_part == 'alice'
        assert addrs[1].local_part == 'bob'

    def test_address_list_three(self):
        p = AddressParser(strict=True)
        addrs = p.parse_address_list('a@x.com, b@x.com, c@x.com')
        assert len(addrs) == 3

    def test_mailbox_list(self):
        p = AddressParser(strict=True)
        mboxes = p.parse_mailbox_list('a@x.com, b@x.com')
        assert len(mboxes) == 2
        for m in mboxes:
            assert not m.is_group

    def test_mailbox_list_rejects_groups(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse_mailbox_list('Group:a@b.com;')

    def test_address_list_with_mixed(self):
        p = AddressParser(strict=True)
        addrs = p.parse_address_list('Group:a@b.com;, c@d.com')
        assert len(addrs) == 2
        assert addrs[0].is_group
        assert not addrs[1].is_group

    def test_source_field_preserved(self):
        p = AddressParser(strict=True)
        r = p.parse('user@example.com')
        assert r.source == 'user@example.com'


# ── §3.4.1 Addr-Spec / Domain-Literal (8+ cases) ──────────────────────────────

class TestAddrSpecDomainLiteral:
    """§3.4.1: addr-spec, domain-literal, IPv4/IPv6"""

    def test_ipv4_domain_literal(self):
        p = AddressParser(strict=True)
        r = p.parse('user@[192.168.1.1]')
        assert r.domain == '[192.168.1.1]'

    def test_ipv6_domain_literal(self):
        p = AddressParser(strict=True)
        r = p.parse('user@[IPv6:2001:db8::1]')
        assert r.domain == '[IPv6:2001:db8::1]'

    def test_full_ipv6_domain_literal(self):
        p = AddressParser(strict=True)
        r = p.parse('postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]')
        assert r.domain == '[IPv6:2001:db8:85a3::8a2e:370:7334]'

    def test_domain_literal_with_tag(self):
        p = AddressParser(strict=True)
        r = p.parse('user+tag@[192.168.1.1]')
        assert r.local_part == 'user+tag'
        assert r.domain == '[192.168.1.1]'

    def test_local_part_max_length(self):
        p = AddressParser(strict=True)
        local = 'a' * 64
        r = p.parse(f'{local}@example.com')
        assert r.local_part == local

    def test_local_part_too_long_strict(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse(f'{"a" * 65}@example.com')

    def test_local_part_consecutive_dots_strict(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('a..b@example.com')

    def test_domain_label_too_long_strict(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse(f'user@{"a" * 64}.com')


# ── §4.4 Obsolete Addressing (8+ cases) ──────────────────────────────────────

class TestObsoleteAddressing:
    """§4.4: obs-local-part, obs-domain, obs-mbox-list, obs-addr-list"""

    def test_obs_domain_leading_dot(self):
        p = AddressParser(strict=False)
        r = p.parse('user@.leading-dot.com')
        assert r.domain == '.leading-dot.com'

    def test_obs_domain_strict_rejects(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('user@.leading-dot.com')

    def test_obs_local_part_mixed(self):
        p = AddressParser(strict=False)
        r = p.parse('user."quoted"@example.com')
        assert r.local_part == 'user."quoted"'

    def test_obs_local_part_strict_rejects(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('user."quoted"@example.com')

    def test_obs_local_part_long_length_permissive(self):
        p = AddressParser(strict=False)
        r = p.parse(f'{"a" * 100}@example.com')
        assert r.local_part == 'a' * 100

    def test_obs_fws_in_address(self):
        p = AddressParser(strict=False)
        r = p.parse('user\r\n @example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_obs_simple_control_char_permissive(self):
        p = AddressParser(strict=False)
        # \x01 in quoted local-part
        r = p.parse('"test\x01char"@example.com')
        assert '\x01' in r.local_part

    def test_strict_mode_default(self):
        p = AddressParser()  # default strict=True
        with pytest.raises(ValueError):
            p.parse('user@.leading-dot.com')


# ── Edge Cases ───────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge cases: max length, empty parts, weird but valid"""

    def test_input_too_long(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('a' * 999 + '@example.com')

    def test_input_998_chars(self):
        p = AddressParser(strict=False)
        # 989 a's + @b.com = 998 chars total
        r = p.parse(f'{"a" * 989}@b.com')
        assert r.local_part == 'a' * 989

    def test_empty_input(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('')

    def test_max_local_part_permissive(self):
        p = AddressParser(strict=False)
        r = p.parse(f'{"a" * 256}@example.com')
        assert r.local_part == 'a' * 256

    def test_stripped_cfws(self):
        p = AddressParser(strict=True)
        r = p.parse('(ignored) user @ example.com (trailing)')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'
        assert len(r.comments) > 0


# ── Invalid/Rejection Cases ──────────────────────────────────────────────────

class TestInvalidRejection:
    """Inputs that should be rejected in strict mode"""

    def test_missing_at_sign(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('userexample.com')

    def test_missing_domain(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('user@')

    def test_missing_local_part(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('@example.com')

    def test_unclosed_angle_bracket(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('<user@example.com')

    def test_unclosed_quoted_string(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('"unclosed@example.com')

    def test_missing_semicolon_in_group(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('Group:user@a.com')

    def test_junk_after_address(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('user@example.com extra')

    def test_unclosed_comment(self):
        p = AddressParser(strict=True)
        with pytest.raises(ValueError):
            p.parse('(unclosed comment user@example.com')


# ── Run with: pytest test_parser.py -v ───────────────────────────────────────
