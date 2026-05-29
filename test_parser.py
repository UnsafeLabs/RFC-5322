#!/usr/bin/env python3
"""Comprehensive test suite for RFC 5322 Address Parser.

Tests are organised by RFC 5322 section:
  §3.2   – Lexical Tokens
  §3.4   – Address Specification
  §3.4.1 – Addr-Spec Specification
  §4.4   – Obsolete Addressing
  §A     – Examples from RFC 5322 Appendix A
  Error  – Error handling and edge cases

Run:
    python -m pytest test_parser.py -v
    python test_parser.py
"""

from __future__ import annotations

import pytest

from parser import (
    AddressParser,
    AddressParserError,
    RFC5322Address,
    parse_address,
    parse_address_list,
    parse_mailbox_list,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _a(display_name=None, local_part=None, domain=None,
       is_group=False, group_mailboxes=None):
    """Factory for expected RFC5322Address values."""
    return RFC5322Address(
        display_name=display_name,
        local_part=local_part,
        domain=domain,
        is_group=is_group,
        group_mailboxes=group_mailboxes or [],
    )


def _strip_raw(addr):
    """Return a copy of *addr* with ``raw`` cleared for comparison."""
    return RFC5322Address(
        display_name=addr.display_name,
        local_part=addr.local_part,
        domain=addr.domain,
        is_group=addr.is_group,
        group_mailboxes=[_strip_raw(m) for m in addr.group_mailboxes],
    )


def _strip_raw_list(lst):
    return [_strip_raw(a) for a in lst]


# ═══════════════════════════════════════════════════════════════════════════
# §3.2  Lexical Tokens
# ═══════════════════════════════════════════════════════════════════════════

class TestLexicalTokens:
    """Tests for RFC 5322 §3.2 — Lexical Tokens."""

    # ── §3.2.1  Quoted characters (quoted-pair) ────────────────────────

    def test_quoted_pair_in_quoted_string(self):
        """quoted-pair inside a quoted-string un-escapes the character."""
        r = parse_address('"test\\"name"@example.com')
        assert r.local_part == 'test"name'

    def test_quoted_pair_backslash_backslash(self):
        """Backslash escaping another backslash."""
        r = parse_address('"test\\\\name"@example.com')
        assert r.local_part == 'test\\name'

    def test_quoted_pair_in_display_name(self):
        """Escaped quote in display-name quoted-string."""
        r = parse_address('"John \\"The Man\\" Doe" <jdoe@example.com>')
        assert r.display_name == 'John "The Man" Doe'

    def test_quoted_pair_in_comment_strict(self):
        """Backslash escapes inside comments (strict mode)."""
        r = parse_address(r'(comment with \) paren) user@example.com')
        assert r.local_part == 'user'

    def test_obs_qp_rejected_strict(self):
        """obs-qp (backslash + control char) rejected in strict mode."""
        with pytest.raises(AddressParserError):
            parse_address('"test\\\x01"@example.com', strict=True)

    def test_obs_qp_accepted_permissive(self):
        """obs-qp accepted with strict=False."""
        r = parse_address('"test\\\x01"@example.com', strict=False)
        assert r.local_part == 'test\x01'

    # ── §3.2.2  Folding White Space and Comments ──────────────────────

    def test_single_space_between_words(self):
        """Single SP between atoms in display-name."""
        r = parse_address('John Doe <jdoe@example.com>')
        assert r.display_name == 'John Doe'

    def test_multiple_spaces_collapse(self):
        """Multiple SP between atoms collapse to one."""
        r = parse_address('John    Doe <jdoe@example.com>')
        assert r.display_name == 'John Doe'

    def test_tab_between_words(self):
        """HTAB between atoms in display-name."""
        r = parse_address('John\tDoe <jdoe@example.com>')
        assert r.display_name == 'John Doe'

    def test_comment_before_address(self):
        """CFWS before addr-spec is skipped."""
        r = parse_address('(a comment) user@example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_comment_after_address_in_angle(self):
        """CFWS after addr-spec inside angle brackets."""
        r = parse_address('<user@example.com (trailing comment)>')
        assert r.local_part == 'user'

    def test_comment_in_display_name(self):
        """Comment between words in display-name."""
        r = parse_address('John (middle name) Doe <jdoe@example.com>')
        assert r.display_name == 'John Doe'

    def test_nested_comments(self):
        """Nested comments are handled correctly."""
        r = parse_address('(outer (inner) still outer) user@example.com')
        assert r.local_part == 'user'

    def test_multiple_comments(self):
        """Multiple consecutive comments."""
        r = parse_address('(one)(two) user@example.com')
        assert r.local_part == 'user'

    def test_comment_inside_angle_addr(self):
        """Comment right after opening angle bracket."""
        r = parse_address('< (comment) user@example.com>')
        assert r.local_part == 'user'

    def test_fws_after_comma_in_list(self):
        """FWS after comma in address list."""
        r = parse_address_list('alice@a.com,   bob@b.com')
        assert len(r) == 2
        assert r[0].local_part == 'alice'
        assert r[1].local_part == 'bob'

    # ── §3.2.3  Atom / dot-atom ───────────────────────────────────────

    def test_atom_simple(self):
        """Simple atom as local-part."""
        r = parse_address('hello@example.com')
        assert r.local_part == 'hello'

    def test_atom_with_allowed_special_chars(self):
        """Atom with atext special characters."""
        r = parse_address("a!b#c$d%e&f'g*h+i-j/k=l?m^n_o`p{q|r}s~t@example.com")
        assert r.local_part == "a!b#c$d%e&f'g*h+i-j/k=l?m^n_o`p{q|r}s~t"

    def test_dot_atom_simple(self):
        """Simple dot-atom."""
        r = parse_address('first.last@example.com')
        assert r.local_part == 'first.last'

    def test_dot_atom_multiple_dots(self):
        """Multiple dots in dot-atom."""
        r = parse_address('a.b.c.d@example.com')
        assert r.local_part == 'a.b.c.d'

    def test_dot_atom_as_domain(self):
        """dot-atom used as domain part."""
        r = parse_address('user@mail.example.co.uk')
        assert r.domain == 'mail.example.co.uk'

    def test_dot_atom_trailing_dot_rejected(self):
        """Trailing dot — dot-atom-text requires 1*atext after each dot."""
        with pytest.raises(AddressParserError):
            parse_address('hello.@example.com')

    def test_atom_leading_dot_fails(self):
        """Leading dot makes dot-atom-text fail."""
        with pytest.raises(AddressParserError):
            parse_address('.hello@example.com')

    def test_atom_consecutive_dots(self):
        """Consecutive dots — dot-atom-text requires 1*atext between dots."""
        with pytest.raises(AddressParserError):
            parse_address('a..b@example.com')

    # ── §3.2.4  Quoted Strings ────────────────────────────────────────

    def test_quoted_string_simple(self):
        """Simple quoted-string as local-part."""
        r = parse_address('"hello world"@example.com')
        assert r.local_part == 'hello world'

    def test_quoted_string_preserves_spaces(self):
        """Spaces inside quoted-string are preserved."""
        r = parse_address('"hello  world"@example.com')
        assert r.local_part == 'hello  world'

    def test_quoted_string_preserves_tabs(self):
        """Tabs inside quoted-string are preserved."""
        r = parse_address('"hello\tworld"@example.com')
        assert r.local_part == 'hello\tworld'

    def test_quoted_string_in_display_name(self):
        """Quoted-string as display-name."""
        r = parse_address('"Doe, John" <jdoe@example.com>')
        assert r.display_name == 'Doe, John'

    def test_quoted_string_with_qtext_specials(self):
        """Characters allowed in qtext (excluding DQUOTE and backslash)."""
        r = parse_address('"! #$%&\'()*+,-./0-9:;<=>?@A-Z[]^_`a-z{|}~"@example.com')
        assert r.local_part is not None

    def test_quoted_string_empty(self):
        """Empty quoted-string is valid."""
        r = parse_address('""@example.com')
        assert r.local_part == ''

    def test_quoted_string_unclosed_rejected(self):
        """Unclosed quoted-string raises error."""
        with pytest.raises(AddressParserError):
            parse_address('"unclosed@example.com')

    def test_quoted_string_with_crlf_strict(self):
        """CRLF inside quoted-string handled (invisible in strict)."""
        r = parse_address('"hello\r\n world"@example.com')
        assert r.local_part == 'hello world'

    # ── §3.2.5  Miscellaneous Tokens (word, phrase) ───────────────────

    def test_phrase_single_word(self):
        """Phrase with a single atom."""
        r = parse_address('Hello <user@example.com>')
        assert r.display_name == 'Hello'

    def test_phrase_multiple_words(self):
        """Phrase with multiple atoms."""
        r = parse_address('John David Doe <jdoe@example.com>')
        assert r.display_name == 'John David Doe'

    def test_phrase_mixed_atom_and_quoted(self):
        """Phrase mixing atoms and quoted-strings."""
        r = parse_address('Dr. "John Doe" Jr. <jdoe@example.com>')
        assert r.display_name == 'Dr. John Doe Jr.'

    def test_phrase_dots_between_atoms(self):
        """Dots between atoms are part of obs-phrase (permissive mode)."""
        r = parse_address('John.Doe <jdoe@example.com>', strict=False)
        assert r.display_name == 'John Doe'

    def test_phrase_dots_between_atoms_rejected_strict(self):
        """Dots between atoms (obs-phrase) rejected in strict mode."""
        with pytest.raises(AddressParserError, match='obs-phrase'):
            parse_address('John.Doe <jdoe@example.com>', strict=True)


# ═══════════════════════════════════════════════════════════════════════════
# §3.4  Address Specification
# ═══════════════════════════════════════════════════════════════════════════

class TestAddressSpecification:
    """Tests for RFC 5322 §3.4 — Address Specification."""

    # ── mailbox ────────────────────────────────────────────────────────

    def test_mailbox_simple_addr_spec(self):
        """Bare addr-spec is a valid mailbox."""
        r = parse_address('user@example.com')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'
        assert r.display_name is None

    def test_mailbox_name_addr(self):
        """name-addr form of mailbox."""
        r = parse_address('John Doe <user@example.com>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_mailbox_name_addr_no_space_before_angle(self):
        """name-addr without space before '<'."""
        r = parse_address('John Doe<user@example.com>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'user'

    def test_mailbox_angle_addr_only(self):
        """Bare angle-addr (no display-name)."""
        r = parse_address('<user@example.com>')
        assert r.display_name is None
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_mailbox_quoted_display_name(self):
        """Display-name as a quoted-string."""
        r = parse_address('"John Doe" <user@example.com>')
        assert r.display_name == 'John Doe'

    def test_name_addr_cfws_around_angle(self):
        """CFWS inside angle brackets."""
        r = parse_address('John < (c1) user (c2) @ (c3) example.com (c4) >')
        assert r.display_name == 'John'
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    # ── group ──────────────────────────────────────────────────────────

    def test_group_empty(self):
        """Empty group (undisclosed recipients)."""
        r = parse_address('undisclosed-recipients:;')
        assert r.is_group
        assert r.display_name == 'undisclosed-recipients'
        assert r.group_mailboxes == []

    def test_group_single_mailbox(self):
        """Group with a single mailbox."""
        r = parse_address('Friends: alice@example.com;')
        assert r.is_group
        assert r.display_name == 'Friends'
        assert len(r.group_mailboxes) == 1
        assert r.group_mailboxes[0].local_part == 'alice'

    def test_group_multiple_mailboxes(self):
        """Group with multiple mailboxes."""
        r = parse_address('Team: alice@a.com, bob@b.com, carol@c.com;')
        assert r.is_group
        assert r.display_name == 'Team'
        assert len(r.group_mailboxes) == 3

    def test_group_multiple_mailboxes_with_names(self):
        """Group mailboxes can have display names."""
        r = parse_address('Team: Alice <alice@a.com>, Bob <bob@b.com>;')
        assert r.is_group
        assert len(r.group_mailboxes) == 2
        assert r.group_mailboxes[0].display_name == 'Alice'
        assert r.group_mailboxes[1].display_name == 'Bob'

    def test_group_cfws_after_colon(self):
        """CFWS between colon and group-list."""
        r = parse_address('Team: (comment) alice@a.com;')
        assert r.is_group
        assert len(r.group_mailboxes) == 1

    def test_group_cfws_before_semicolon(self):
        """CFWS before closing semicolon."""
        r = parse_address('Team: alice@a.com (comment);')
        assert r.is_group
        assert len(r.group_mailboxes) == 1

    def test_group_not_closed_rejected(self):
        """Group without closing semicolon is rejected."""
        with pytest.raises(AddressParserError):
            parse_address('Team: alice@a.com')

    def test_group_missing_colon_rejected(self):
        """Group missing colon is parsed as addr-spec instead."""
        with pytest.raises(AddressParserError):
            parse_address('Team alice@a.com;')

    # ── address-list ───────────────────────────────────────────────────

    def test_address_list_two_simple(self):
        """Two simple addresses in a list."""
        r = parse_address_list('alice@a.com, bob@b.com')
        assert len(r) == 2

    def test_address_list_mixed_types(self):
        """List containing both bare addr-spec and name-addr."""
        r = parse_address_list('user@host.com, John <john@host.com>')
        assert len(r) == 2
        assert r[0].display_name is None
        assert r[1].display_name == 'John'

    def test_address_list_with_group(self):
        """Address list can contain group addresses."""
        r = parse_address_list('alice@a.com, Group: bob@b.com, carol@c.com;')
        assert len(r) == 2
        assert not r[0].is_group
        assert r[1].is_group

    def test_address_list_single_address(self):
        """Address list with a single address."""
        r = parse_address_list('user@example.com')
        assert len(r) == 1

    def test_address_list_with_cfws(self):
        """CFWS around commas in address list."""
        r = parse_address_list('a@b.c (c1) , (c2) d@e.f')
        assert len(r) == 2

    # ── mailbox-list ───────────────────────────────────────────────────

    def test_mailbox_list_simple(self):
        """Simple mailbox list."""
        r = parse_mailbox_list('alice@a.com, bob@b.com')
        assert len(r) == 2
        assert not r[0].is_group
        assert not r[1].is_group

    def test_mailbox_list_rejects_group_strict(self):
        """mailbox-list rejects group construct (groups not mailboxes)."""
        with pytest.raises(AddressParserError):
            parse_mailbox_list('Group: alice@a.com;')


# ═══════════════════════════════════════════════════════════════════════════
# §3.4.1  Addr-Spec Specification
# ═══════════════════════════════════════════════════════════════════════════

class TestAddrSpec:
    """Tests for RFC 5322 §3.4.1 — Addr-Spec Specification."""

    # ── local-part ─────────────────────────────────────────────────────

    def test_local_part_dot_atom(self):
        """local-part as dot-atom."""
        r = parse_address('john.doe@example.com')
        assert r.local_part == 'john.doe'

    def test_local_part_quoted_string(self):
        """local-part as quoted-string."""
        r = parse_address('"john doe"@example.com')
        assert r.local_part == 'john doe'

    def test_local_part_quoted_string_with_escape(self):
        """quoted-string local-part with quoted-pair."""
        r = parse_address('"john \\"doe\\""@example.com')
        assert r.local_part == 'john "doe"'

    def test_local_part_case_preserved(self):
        """local-part case is preserved."""
        r = parse_address('John.Doe@Example.COM')
        assert r.local_part == 'John.Doe'

    # ── domain ─────────────────────────────────────────────────────────

    def test_domain_dot_atom(self):
        """Domain as dot-atom."""
        r = parse_address('user@example.com')
        assert r.domain == 'example.com'

    def test_domain_subdomains(self):
        """Domain with multiple subdomains."""
        r = parse_address('user@mail.eng.example.com')
        assert r.domain == 'mail.eng.example.com'

    def test_domain_literal_ipv4(self):
        """Domain-literal with IPv4 address."""
        r = parse_address('user@[127.0.0.1]')
        assert r.domain == '[127.0.0.1]'

    def test_domain_literal_ipv6(self):
        """Domain-literal with IPv6 address."""
        r = parse_address('user@[IPv6:2001:db8::1]')
        assert r.domain == '[IPv6:2001:db8::1]'

    def test_domain_literal_with_cfws(self):
        """Domain-literal with CFWS inside brackets."""
        r = parse_address('user@[ (comment) 127.0.0.1 ]')
        assert r.domain == '[127.0.0.1]'

    def test_domain_literal_tag(self):
        """Domain-literal with a tag."""
        r = parse_address('user@[some-tag]')
        assert r.domain == '[some-tag]'

    # ── addr-spec full ─────────────────────────────────────────────────

    def test_addr_spec_minimal(self):
        """Minimal valid addr-spec."""
        r = parse_address('a@b.c')
        assert r.local_part == 'a'
        assert r.domain == 'b.c'
        assert r.display_name is None

    def test_addr_spec_common_form(self):
        """Common email address form."""
        r = parse_address('first.last@example.com')
        assert r.local_part == 'first.last'
        assert r.domain == 'example.com'

    def test_addr_spec_missing_at_rejected(self):
        """Missing @ rejected."""
        with pytest.raises(AddressParserError):
            parse_address('noat.example.com')

    def test_addr_spec_missing_domain_rejected(self):
        """Missing domain after @."""
        with pytest.raises(AddressParserError):
            parse_address('user@')

    def test_addr_spec_double_at_rejected(self):
        """Double @ rejected."""
        with pytest.raises(AddressParserError):
            parse_address('user@host@extra.com')

    def test_addr_spec_only_at_rejected(self):
        """Only @ with no local-part."""
        with pytest.raises(AddressParserError):
            parse_address('@example.com')


# ═══════════════════════════════════════════════════════════════════════════
# §4.4  Obsolete Addressing (strict=False)
# ═══════════════════════════════════════════════════════════════════════════

class TestObsoleteAddressing:
    """Tests for RFC 5322 §4.4 — Obsolete Addressing (permissive mode)."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.p = AddressParser(strict=False)
        self.ps = AddressParser(strict=True)

    # ── obs-angle-addr / obs-route ─────────────────────────────────────

    def test_obs_angle_addr_single_hop(self):
        """Source route with one relay."""
        r = self.p.parse('<@relay.com:user@final.com>')
        assert r.local_part == 'user'
        assert r.domain == 'final.com'

    def test_obs_angle_addr_multi_hop(self):
        """Source route with multiple relays."""
        r = self.p.parse('<@hosta.int,@hostb.int:user@example.com>')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'

    def test_obs_angle_addr_with_display_name(self):
        """Source route with display name."""
        r = self.p.parse('John Doe <@relay.com:user@final.com>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'user'
        assert r.domain == 'final.com'

    def test_obs_angle_addr_rejected_strict(self):
        """obs-angle-addr rejected in strict mode."""
        with pytest.raises(AddressParserError):
            self.ps.parse('<@relay.com:user@final.com>')

    # ── obs-local-part ─────────────────────────────────────────────────

    def test_obs_local_part_with_dots(self):
        """obs-local-part allows word *('.' word)."""
        r = self.p.parse('"hello"."world"@example.com')
        assert r.local_part == 'hello.world'

    def test_obs_local_part_atom_and_quoted(self):
        """obs-local-part mixing atoms and quoted strings."""
        r = self.p.parse('hello."world"@example.com')
        assert r.local_part == 'hello.world'

    # ── obs-domain ─────────────────────────────────────────────────────

    def test_obs_domain_atoms(self):
        """obs-domain: atom *('.' atom) (non-strict fallback)."""
        r = self.p.parse('user@domain.com')
        assert r.domain == 'domain.com'

    # ── obs-mbox-list ──────────────────────────────────────────────────

    def test_obs_mbox_list_trailing_comma(self):
        """obs-mbox-list allows trailing comma."""
        r = self.p.parse_mailbox_list('alice@a.com, bob@b.com,')
        assert len(r) == 2

    def test_obs_mbox_list_leading_comma(self):
        """obs-mbox-list allows leading comma."""
        r = self.p.parse_mailbox_list(', alice@a.com, bob@b.com')
        assert len(r) == 2

    def test_obs_mbox_list_empty_elements(self):
        """obs-mbox-list allows empty elements (,,)."""
        r = self.p.parse_mailbox_list('alice@a.com,, bob@b.com')
        assert len(r) == 2

    # ── obs-addr-list ──────────────────────────────────────────────────

    def test_obs_addr_list_trailing_comma(self):
        """obs-addr-list allows trailing comma."""
        r = self.p.parse_address_list('alice@a.com, bob@b.com,')
        assert len(r) == 2

    def test_obs_addr_list_leading_comma(self):
        """obs-addr-list allows leading comma."""
        r = self.p.parse_address_list(', alice@a.com')
        assert len(r) == 1

    # ── obs-group-list ─────────────────────────────────────────────────

    def test_obs_group_list_empty_with_commas(self):
        """obs-group-list: commas only between : and ;."""
        r = self.p.parse('EmptyGroup:,,;')
        assert r.is_group
        assert r.group_mailboxes == []


# ═══════════════════════════════════════════════════════════════════════════
# RFC 5322 Appendix A  — Example Messages (Addressing Examples)
# ═══════════════════════════════════════════════════════════════════════════

class TestAppendixA:
    """Tests drawn from RFC 5322 Appendix A addressing examples."""

    def test_simple_from_example(self):
        """A.1.1 — Simple addressing: From: John Doe <jdoe@machine.example>"""
        r = parse_address('John Doe <jdoe@machine.example>')
        assert r.display_name == 'John Doe'
        assert r.local_part == 'jdoe'
        assert r.domain == 'machine.example'

    def test_mailbox_types_example(self):
        """A.1.2 — Different types of mailboxes."""
        r = parse_address('jdoe@machine.example')
        assert r.local_part == 'jdoe'
        assert r.domain == 'machine.example'

    def test_group_example(self):
        """A.1.3 — Group address: A Group:Chris Jones <c@a.test>,..."""
        r = parse_address(
            'A Group:Chris Jones <c@a.test>,'
            'john@b.test, John <jdoe@machine.test>;'
        )
        assert r.is_group
        assert r.display_name == 'A Group'
        assert len(r.group_mailboxes) == 3
        assert r.group_mailboxes[0].display_name == 'Chris Jones'
        assert r.group_mailboxes[2].display_name == 'John'

    def test_empty_group_example(self):
        """A.1.3 — Empty group: undisclosed-recipients:;"""
        r = parse_address('undisclosed-recipients:;')
        assert r.is_group
        assert r.display_name == 'undisclosed-recipients'
        assert r.group_mailboxes == []

    def test_white_space_oddities_example(self):
        """A.5 — White space and comments oddities."""
        r = parse_address('< (comment)   user@example.com (another)  >')
        assert r.local_part == 'user'
        assert r.domain == 'example.com'


# ═══════════════════════════════════════════════════════════════════════════
# Error handling / edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorHandling:
    """Tests for error conditions and edge cases."""

    def test_empty_string_rejected(self):
        """Empty input raises error."""
        with pytest.raises(AddressParserError):
            parse_address('')

    def test_whitespace_only_rejected(self):
        """Whitespace-only input raises error."""
        with pytest.raises(AddressParserError):
            parse_address('   ')

    def test_line_too_long_rejected(self):
        """Input exceeding 998 characters rejected."""
        long_input = 'a' * 999 + '@b.com'
        with pytest.raises(AddressParserError, match='exceeds'):
            parse_address(long_input)

    def test_trailing_garbage_rejected(self):
        """Content after the address is rejected."""
        with pytest.raises(AddressParserError, match='trailing'):
            parse_address('user@example.com GARBAGE')

    def test_unclosed_angle_bracket(self):
        """Missing closing '>' rejected."""
        with pytest.raises(AddressParserError):
            parse_address('<user@example.com')

    def test_unopened_angle_bracket(self):
        """Closing '>' without opening '<'."""
        with pytest.raises(AddressParserError):
            parse_address('user@example.com>')

    def test_address_parser_error_attributes(self):
        """AddressParserError has pos and context attributes."""
        try:
            parse_address('not(valid')
        except AddressParserError as e:
            assert hasattr(e, 'pos')
            assert hasattr(e, 'context')
            assert isinstance(e.pos, int)
            assert isinstance(e.context, str)

    def test_parse_address_list_empty_string(self):
        """Empty address list raises error."""
        with pytest.raises(AddressParserError):
            parse_address_list('')

    def test_parse_mailbox_list_empty_string(self):
        """Empty mailbox list raises error."""
        with pytest.raises(AddressParserError):
            parse_mailbox_list('')

    def test_max_line_length_default(self):
        """MAX_LINE_LENGTH is 998 (RFC 5322 §2.1.1)."""
        assert AddressParser.MAX_LINE_LENGTH == 998


# ═══════════════════════════════════════════════════════════════════════════
# Strict vs. non-strict mode
# ═══════════════════════════════════════════════════════════════════════════

class TestStrictMode:
    """Tests for strict (default) vs. permissive (strict=False) behaviour."""

    def test_default_is_strict(self):
        """AddressParser default mode is strict."""
        p = AddressParser()
        assert p._strict is True

    def test_permissive_constructor(self):
        """AddressParser(strict=False) is permissive."""
        p = AddressParser(strict=False)
        assert p._strict is False

    def test_module_function_default_strict(self):
        """Module-level parse_address defaults to strict."""
        with pytest.raises(AddressParserError):
            parse_address('<@relay.com:user@final.com>')

    def test_module_function_permissive(self):
        """Module-level parse_address accepts strict=False."""
        r = parse_address('<@relay.com:user@final.com>', strict=False)
        assert r.local_part == 'user'
        assert r.domain == 'final.com'

    def test_standard_valid_in_both_modes(self):
        """Valid standard addresses parse in both modes."""
        addr = 'user@example.com'
        r1 = parse_address(addr, strict=True)
        r2 = parse_address(addr, strict=False)
        assert r1.local_part == r2.local_part
        assert r1.domain == r2.domain


# ═══════════════════════════════════════════════════════════════════════════
# Data model tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDataModel:
    """Tests for the RFC5322Address dataclass."""

    def test_repr_simple(self):
        """repr for simple address."""
        a = RFC5322Address(local_part='user', domain='example.com')
        r = repr(a)
        assert 'user' in r
        assert 'example.com' in r
        assert 'is_group' not in r

    def test_repr_group(self):
        """repr for group address."""
        a = RFC5322Address(
            display_name='Group',
            is_group=True,
            group_mailboxes=[RFC5322Address(local_part='u', domain='d')],
        )
        r = repr(a)
        assert 'Group' in r
        assert 'is_group=True' in r

    def test_raw_attribute_set(self):
        """raw attribute contains the parsed substring."""
        r = parse_address('John <user@example.com>')
        assert r.raw == 'John <user@example.com>'

    def test_strip_raw_helper(self):
        """_strip_raw clears the raw attribute."""
        r = parse_address('user@example.com')
        s = _strip_raw(r)
        assert s.raw == ''

    def test_default_values(self):
        """Default values for RFC5322Address."""
        a = RFC5322Address()
        assert a.display_name is None
        assert a.local_part is None
        assert a.domain is None
        assert a.is_group is False
        assert a.group_mailboxes == []


# ═══════════════════════════════════════════════════════════════════════════
# Test runner (when executed directly, without pytest)
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import sys

    def run_tests():
        total = 0
        passed = 0
        failed = 0
        errors = []

        import inspect
        current_module = sys.modules[__name__]
        test_classes = []
        for name, obj in inspect.getmembers(current_module):
            if (inspect.isclass(obj)
                    and name.startswith('Test')
                    and obj.__module__ == current_module.__name__):
                test_classes.append(obj)

        for cls in test_classes:
            print(f'\n{"="*60}')
            print(f' {cls.__name__}')
            print(f'{"="*60}')
            instance = cls()
            for tname in sorted(dir(instance)):
                if not tname.startswith('test_'):
                    continue
                method = getattr(instance, tname)
                total += 1
                try:
                    if hasattr(instance, 'setup') and callable(instance.setup):
                        instance.setup()
                    method()
                    passed += 1
                    print(f'  PASS {tname}')
                except Exception as e:
                    failed += 1
                    msg = f'  FAIL {tname}: {e}'
                    print(msg)
                    errors.append(msg)

        print(f'\n{"="*60}')
        print(f' Results: {passed}/{total} passed, {failed} failed')
        print(f'{"="*60}')

        return failed == 0

    success = run_tests()
    sys.exit(0 if success else 1)
