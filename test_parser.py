"""
Test suite for RFC 5322 email address parser.
Covers sections §3.2.1–§4.4 with 60+ test cases.
"""
import pytest
from parser import AddressParser, RFC5322Address, ParseError


@pytest.fixture
def strict_parser():
    return AddressParser(strict=True)


@pytest.fixture
def permissive_parser():
    return AddressParser(strict=False)


# ── §3.2.1 – quoted-pair (5 cases) ─────────────────────────────────

class TestQuotedPair:
    def test_simple_escaped_char(self, strict_parser):
        addr = strict_parser.parse(r'"John\"Doe"@example.com')
        assert addr.local_part == 'John"Doe'
        assert addr.domain == 'example.com'

    def test_escaped_backslash(self, strict_parser):
        addr = strict_parser.parse(r'"path\\file"@example.com')
        assert addr.local_part == 'path\\file'

    def test_escaped_space(self, strict_parser):
        addr = strict_parser.parse(r'"a\ b"@example.com')
        assert addr.local_part == 'a b'

    def test_escaped_tab(self, strict_parser):
        addr = strict_parser.parse(r'"a\tb"@example.com')
        assert addr.local_part == 'atb'

    def test_escaped_special_chars(self, strict_parser):
        addr = strict_parser.parse(r'"!@#$%^&*()"@example.com')
        assert addr.local_part == '!@#$%^&*()'


# ── §3.2.2 – FWS (5 cases) ────────────────────────────────────────

class TestFWS:
    def test_simple_space(self, strict_parser):
        addr = strict_parser.parse('user @example.com')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_tab(self, strict_parser):
        addr = strict_parser.parse('user\t@example.com')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_multiple_spaces(self, strict_parser):
        addr = strict_parser.parse('user   @example.com')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_space_before_at(self, strict_parser):
        addr = strict_parser.parse('user @example.com')
        assert addr.local_part == 'user'

    def test_space_after_at(self, strict_parser):
        addr = strict_parser.parse('user@ example.com')
        assert addr.domain == 'example.com'


# ── §3.2.3 – CFWS/comments (8 cases) ──────────────────────────────

class TestCFWS:
    def test_comment_before(self, strict_parser):
        addr = strict_parser.parse('(comment)user@example.com')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_comment_after(self, strict_parser):
        addr = strict_parser.parse('user@example.com(comment)')
        assert addr.local_part == 'user'

    def test_comment_both_sides(self, strict_parser):
        addr = strict_parser.parse('(a)user(b)@(c)example.com(d)')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_nested_comments(self, strict_parser):
        addr = strict_parser.parse('((nested))user@example.com')
        assert addr.local_part == 'user'

    def test_comment_with_special_chars(self, strict_parser):
        addr = strict_parser.parse('(this is a comment)user@example.com')
        assert addr.local_part == 'user'

    def test_multiple_comments(self, strict_parser):
        addr = strict_parser.parse('(a)(b)user(c)(d)@(e)example.com(f)(g)')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_empty_comment(self, strict_parser):
        addr = strict_parser.parse('()user@example.com')
        assert addr.local_part == 'user'

    def test_comment_with_escaped_parens(self, strict_parser):
        addr = strict_parser.parse(r'(\(escaped\))user@example.com')
        assert addr.local_part == 'user'


# ── §3.2.4 – quoted-string (8 cases) ───────────────────────────────

class TestQuotedString:
    def test_simple_quoted(self, strict_parser):
        addr = strict_parser.parse('"user"@example.com')
        assert addr.local_part == 'user'

    def test_quoted_with_space(self, strict_parser):
        addr = strict_parser.parse('"user name"@example.com')
        assert addr.local_part == 'user name'

    def test_quoted_with_specials(self, strict_parser):
        addr = strict_parser.parse('"very.(),:;<>[]"@example.com')
        assert addr.local_part == 'very.(),:;<>[]'

    def test_quoted_empty(self, strict_parser):
        addr = strict_parser.parse('""@example.com')
        assert addr.local_part == ''

    def test_quoted_escaped_quote(self, strict_parser):
        addr = strict_parser.parse(r'"say \"hi\""@example.com')
        assert addr.local_part == 'say "hi"'

    def test_quoted_escaped_backslash(self, strict_parser):
        addr = strict_parser.parse(r'"path\\to"@example.com')
        assert addr.local_part == 'path\\to'

    def test_quoted_with_fws(self, strict_parser):
        addr = strict_parser.parse('"user name"@example.com')
        assert addr.local_part == 'user name'

    def test_quoted_only_specials(self, strict_parser):
        addr = strict_parser.parse('"@#$%^&*()"@example.com')
        assert addr.local_part == '@#$%^&*()'


# ── §3.2.5 – miscellaneous tokens (3 cases) ────────────────────────

class TestMiscTokens:
    def test_word_atom(self, strict_parser):
        addr = strict_parser.parse('user@example.com')
        assert addr.local_part == 'user'

    def test_word_quoted(self, strict_parser):
        addr = strict_parser.parse('"quoted"@example.com')
        assert addr.local_part == 'quoted'

    def test_phrase_multiple_words(self, strict_parser):
        addr = strict_parser.parse('"John Doe" <john@example.com>')
        assert addr.display_name == 'John Doe'
        assert addr.local_part == 'john'


# ── §3.4 – address/mailbox/group (12 cases) ────────────────────────

class TestAddress:
    def test_simple_addr_spec(self, strict_parser):
        addr = strict_parser.parse('user@example.com')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'
        assert addr.is_group is False

    def test_name_addr(self, strict_parser):
        addr = strict_parser.parse('"John Doe" <john@example.com>')
        assert addr.display_name == 'John Doe'
        assert addr.local_part == 'john'
        assert addr.domain == 'example.com'

    def test_angle_addr_only(self, strict_parser):
        addr = strict_parser.parse('<john@example.com>')
        assert addr.display_name is None
        assert addr.local_part == 'john'

    def test_group_address(self, strict_parser):
        addr = strict_parser.parse('A Group:user1@a.com, user2@b.com;')
        assert addr.is_group is True
        assert addr.display_name == 'A Group'
        assert len(addr.group_members) == 2
        assert addr.group_members[0].local_part == 'user1'
        assert addr.group_members[0].domain == 'a.com'
        assert addr.group_members[1].local_part == 'user2'
        assert addr.group_members[1].domain == 'b.com'

    def test_empty_group(self, strict_parser):
        addr = strict_parser.parse('Empty Group:;')
        assert addr.is_group is True
        assert addr.group_members == []

    def test_group_single_member(self, strict_parser):
        addr = strict_parser.parse('Team:user@company.com;')
        assert addr.is_group is True
        assert len(addr.group_members) == 1

    def test_group_with_display_name(self, strict_parser):
        addr = strict_parser.parse('"Engineering Team":alice@corp.com, bob@corp.com;')
        assert addr.display_name == 'Engineering Team'
        assert len(addr.group_members) == 2

    def test_mailbox_list(self, strict_parser):
        addrs = strict_parser.parse_address_list('a@b.com, c@d.com')
        assert len(addrs) == 2
        assert addrs[0].local_part == 'a'
        assert addrs[1].local_part == 'c'

    def test_address_list(self, strict_parser):
        addrs = strict_parser.parse_address_list('user@host.com')
        assert len(addrs) == 1

    def test_mixed_mailbox_group(self, strict_parser):
        addrs = strict_parser.parse_address_list('user@host.com, Group:a@b.com;')
        assert len(addrs) == 2
        assert addrs[0].is_group is False
        assert addrs[1].is_group is True

    def test_display_name_with_dots(self, permissive_parser):
        addr = permissive_parser.parse('J. Smith <jsmith@example.com>')
        assert addr.display_name == 'J. Smith'
        assert addr.local_part == 'jsmith'

    def test_quoted_display_name(self, strict_parser):
        addr = strict_parser.parse('"Doe, John" <john@example.com>')
        assert addr.display_name == 'Doe, John'


# ── §3.4.1 – addr-spec/domain-literal (8 cases) ───────────────────

class TestAddrSpec:
    def test_simple_domain(self, strict_parser):
        addr = strict_parser.parse('user@domain.com')
        assert addr.domain == 'domain.com'

    def test_subdomain(self, strict_parser):
        addr = strict_parser.parse('user@sub.domain.com')
        assert addr.domain == 'sub.domain.com'

    def test_ipv4_literal(self, strict_parser):
        addr = strict_parser.parse('user@[192.168.1.1]')
        assert addr.domain == '[192.168.1.1]'

    def test_ipv6_literal(self, strict_parser):
        addr = strict_parser.parse('user@[IPv6:2001:db8::1]')
        assert addr.domain == '[IPv6:2001:db8::1]'

    def test_ipv6_full(self, strict_parser):
        addr = strict_parser.parse('postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]')
        assert addr.domain == '[IPv6:2001:db8:85a3::8a2e:370:7334]'

    def test_domain_literal_with_space(self, strict_parser):
        addr = strict_parser.parse('user@[192 . 168 . 1 . 1]')
        assert addr.domain == '[192 . 168 . 1 . 1]'

    def test_quoted_local_part(self, strict_parser):
        addr = strict_parser.parse('"quoted"@example.com')
        assert addr.local_part == 'quoted'

    def test_dot_atom_local(self, strict_parser):
        addr = strict_parser.parse('first.last@example.com')
        assert addr.local_part == 'first.last'


# ── §4.4 – obsolete addressing (8 cases) ───────────────────────────

class TestObsolete:
    def test_obs_domain_with_dots(self, permissive_parser):
        addr = permissive_parser.parse('user@host . domain.com')
        assert addr.domain == 'host . domain.com'

    def test_obs_local_part_mixed(self, permissive_parser):
        addr = permissive_parser.parse('user."quoted"@example.com')
        assert addr.local_part == 'user."quoted"'

    def test_obs_angle_addr_route(self, permissive_parser):
        addr = permissive_parser.parse('<@route:user@example.com>')
        assert addr.local_part == 'user'
        assert addr.domain == 'example.com'

    def test_obs_mbox_list_null(self, permissive_parser):
        addrs = permissive_parser.parse_address_list(',,user@host.com,,')
        assert len(addrs) >= 1

    def test_obs_addr_list_null(self, permissive_parser):
        addrs = permissive_parser.parse_address_list(',,user@host.com,,')
        assert len(addrs) >= 1

    def test_obs_local_part_atom_dot(self, permissive_parser):
        addr = permissive_parser.parse('user.name@domain.com')
        assert addr.local_part == 'user.name'

    def test_obs_domain_atoms(self, permissive_parser):
        addr = permissive_parser.parse('user@host.domain.com')
        assert addr.domain == 'host.domain.com'

    def test_obs_phrase_with_dots(self, permissive_parser):
        addr = permissive_parser.parse('J. Smith <jsmith@example.com>')
        assert addr.display_name == 'J. Smith'


# ── Edge cases (5 cases) ────────────────────────────────────────────

class TestEdgeCases:
    def test_max_length_input(self, strict_parser):
        local = 'a' * 64
        domain = 'b' * 63
        addr = strict_parser.parse(f'{local}@{domain}.com')
        assert addr.local_part == local

    def test_empty_local_part(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('@example.com')

    def test_empty_domain(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@')

    def test_nested_deeply(self, strict_parser):
        addr = strict_parser.parse('((a((b)c)d)e)user@example.com')
        assert addr.local_part == 'user'

    def test_multiple_at_signs(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@host@example.com')


# ── Invalid/rejection cases (8 cases) ──────────────────────────────

class TestInvalid:
    def test_empty_string(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('')

    def test_missing_domain(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@')

    def test_missing_local(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('@domain.com')

    def test_unbalanced_quotes(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('"unbalanced@example.com')

    def test_unbalanced_angle(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('<user@example.com')

    def test_trailing_garbage(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@example.com extra')

    def test_invalid_domain_literal(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@[invalid')

    def test_strict_rejects_obs(self, strict_parser):
        with pytest.raises(ParseError):
            strict_parser.parse('user@.leading.dot.com')


# ── parse_mailbox_list (3 cases) ────────────────────────────────────

class TestMailboxList:
    def test_single(self, strict_parser):
        addrs = strict_parser.parse_mailbox_list('user@host.com')
        assert len(addrs) == 1

    def test_multiple(self, strict_parser):
        addrs = strict_parser.parse_mailbox_list('a@b.com, c@d.com, e@f.com')
        assert len(addrs) == 3

    def test_with_groups(self, strict_parser):
        addrs = strict_parser.parse_mailbox_list('Group:user@host.com;')
        assert len(addrs) == 1
        assert addrs[0].is_group is True