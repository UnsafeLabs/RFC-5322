"""Test suite for the RFC 5322 conformant address parser.

Organized by RFC section to mirror the compliance matrix in
``compliance.md``:

    §3.2.1  quoted-pair
    §3.2.2  FWS
    §3.2.3  CFWS / comments
    §3.2.4  quoted-string
    §3.2.5  miscellaneous tokens (word / phrase)
    §3.4    address / mailbox / group / lists
    §3.4.1  addr-spec / domain-literal
    §4.4    obsolete addressing (permissive mode)
    edge    limits, empty parts, nested comments
    invalid rejection cases

Run with:  python -m pytest test_parser.py
"""

from __future__ import annotations

import pytest

from parser import AddressParser, AddressParseError, RFC5322Address


def parse(raw: str, strict: bool = True) -> RFC5322Address:
    return AddressParser(strict=strict).parse(raw)


def parse_list(raw: str, strict: bool = True) -> list[RFC5322Address]:
    return AddressParser(strict=strict).parse_address_list(raw)


def parse_mboxes(raw: str, strict: bool = True) -> list[RFC5322Address]:
    return AddressParser(strict=strict).parse_mailbox_list(raw)


def rejects(raw: str, strict: bool = True) -> None:
    with pytest.raises(AddressParseError):
        parse(raw, strict=strict)


# ===========================================================================
# §3.2.1  quoted-pair
# ===========================================================================


class TestQuotedPair:
    def test_escaped_quote(self) -> None:
        assert parse(r'"quoted\"string"@example.com').local_part == 'quoted"string'

    def test_escaped_backslash(self) -> None:
        assert parse(r'"back\\slash"@example.com').local_part == r"back\slash"

    def test_escaped_specials(self) -> None:
        # Escaping punctuation that would otherwise be specials.
        assert parse(r'"\@\$\#\^"@example.com').local_part == "@$#^"

    def test_escaped_parens_in_comment(self) -> None:
        # quoted-pair may appear inside comments: the ")" is escaped and
        # does not terminate the comment.
        addr = parse(r"(\a\)b)user@example.com")
        assert addr.comments == ["a)b"]

    def test_escaped_backslash_at_content_end(self) -> None:
        assert parse(r'"a\\"@example.com').local_part == "a\\"

    def test_escaped_space(self) -> None:
        # quoted-pair = "\" (VCHAR / WSP); a quoted-pair may escape WSP.
        assert parse(r'"\ "@example.com').local_part == " "

    def test_dangling_backslash_rejected(self) -> None:
        # A trailing backslash cannot form a quoted-pair.
        rejects(r'"abc\"@example.com')


# ===========================================================================
# §3.2.2  FWS
# ===========================================================================


class TestFWS:
    def test_fws_after_at_sign(self) -> None:
        addr = parse("user@ example.com")
        assert (addr.local_part, addr.domain) == ("user", "example.com")

    def test_folding_after_at_sign(self) -> None:
        # ([*WSP CRLF] 1*WSP): CRLF followed by WSP is a legal fold.
        addr = parse("user@\r\n example.com")
        assert addr.domain == "example.com"

    def test_folding_after_local_part(self) -> None:
        addr = parse("user\r\n @example.com")
        assert (addr.local_part, addr.domain) == ("user", "example.com")

    def test_fws_between_display_name_words(self) -> None:
        addr = parse("John\r\n Doe <john@example.com>")
        assert addr.display_name == "John Doe"

    def test_fws_inside_quoted_string(self) -> None:
        # FWS inside a quoted-string collapses to a single space.
        assert parse('"abc\r\n def"@example.com').local_part == "abc def"

    def test_fws_inside_comment(self) -> None:
        addr = parse("(abc\r\n def)user@example.com")
        assert addr.comments == ["abc def"]

    def test_fws_collapses_runs(self) -> None:
        assert parse('"a  b"@example.com').local_part == "a b"

    def test_double_fold_requires_obs(self) -> None:
        # Two consecutive folds make a line of pure WSP -> obs-FWS only.
        rejects("user@ \r\n \r\n example.com", strict=True)
        assert parse("user@ \r\n \r\n example.com", strict=False).domain == "example.com"


# ===========================================================================
# §3.2.3  CFWS / comments
# ===========================================================================


class TestCFWS:
    def test_leading_comment(self) -> None:
        addr = parse("(comment)user@example.com")
        assert (addr.local_part, addr.domain) == ("user", "example.com")
        assert addr.comments == ["comment"]

    def test_comment_in_domain(self) -> None:
        addr = parse("user@(comment)example.com")
        assert addr.domain == "example.com"
        assert addr.comments == ["comment"]

    def test_comment_between_tokens(self) -> None:
        addr = parse("(comment)user(mid)@(end)example.com")
        assert (addr.local_part, addr.domain) == ("user", "example.com")
        assert addr.comments == ["comment", "mid", "end"]

    def test_nested_comments(self) -> None:
        addr = parse("(outer(inner))user@example.com")
        assert set(addr.comments) == {"outer(inner)", "inner"}

    def test_multiple_comments_with_fws(self) -> None:
        addr = parse("(one) (two)user@example.com")
        assert addr.comments == ["one", "two"]

    def test_empty_comment(self) -> None:
        addr = parse("()user@example.com")
        assert addr.comments == [""]

    def test_comment_in_display_name(self) -> None:
        addr = parse("John (comment) Doe <jdoe@example.com>")
        assert addr.display_name == "John Doe"
        assert addr.comments == ["comment"]

    def test_comment_before_angle_bracket(self) -> None:
        addr = parse("John Doe (x) <jdoe@example.com>")
        assert addr.display_name == "John Doe"
        assert addr.comments == ["x"]

    def test_comment_with_specials_in_comment(self) -> None:
        # The "." in the comment is a special but is legal inside a comment.
        addr = parse("user@(Chris's host.)public.example")
        assert addr.domain == "public.example"
        assert addr.comments == ["Chris's host."]

    def test_cfws_around_domain_literal(self) -> None:
        addr = parse("user@(c)[192.168.1.1]")
        assert addr.domain == "192.168.1.1"
        assert addr.comments == ["c"]


# ===========================================================================
# §3.2.4  quoted-string
# ===========================================================================


class TestQuotedString:
    def test_quoted_display_name(self) -> None:
        addr = parse('"John Doe" <john@example.com>')
        assert addr.display_name == "John Doe"
        assert (addr.local_part, addr.domain) == ("john", "example.com")

    def test_single_space_local_part(self) -> None:
        assert parse('" "@example.com').local_part == " "

    def test_empty_quoted_local_part(self) -> None:
        # *([FWS] qcontent) permits zero qcontent.
        assert parse('""@example.com').local_part == ""

    def test_all_specials_escaped(self) -> None:
        # Every special character appears inside the quoted-string.
        addr = parse(r'"very.(),:;<>\"@[]\\ long"@example.com')
        assert addr.local_part == r'very.(),:;<>"@[]\ long'

    def test_fws_collapse(self) -> None:
        assert parse('"abc def"@example.com').local_part == "abc def"

    def test_fold_within_quoted_string(self) -> None:
        assert parse('"abc\r\n def"@example.com').local_part == "abc def"

    def test_cfws_before_quoted_local_part(self) -> None:
        addr = parse('(c)"quoted"@example.com')
        assert addr.local_part == "quoted"
        assert addr.comments == ["c"]

    def test_quoted_display_name_with_colon(self) -> None:
        addr = parse('"Mary Smith: Personal Account" <smith@home.example>')
        assert addr.display_name == "Mary Smith: Personal Account"

    def test_quoted_display_name_with_escaped_quote(self) -> None:
        addr = parse('"Giant; \\"Big\\" Box" <sysservices@example.net>')
        assert addr.display_name == 'Giant; "Big" Box'

    def test_control_char_in_qtext_rejected(self) -> None:
        # obs-qtext (control chars) must be rejected in strict mode.
        rejects('"a\x01b"@example.com', strict=True)
        assert parse('"a\x01b"@example.com', strict=False).local_part == "a\x01b"


# ===========================================================================
# §3.2.5  miscellaneous tokens (word / phrase)
# ===========================================================================


class TestMiscTokens:
    def test_atom_word(self) -> None:
        addr = parse("user@example.com")
        assert (addr.local_part, addr.domain) == ("user", "example.com")

    def test_phrase_display_name(self) -> None:
        addr = parse("John Doe <jdoe@example.com>")
        assert addr.display_name == "John Doe"

    def test_quoted_string_word(self) -> None:
        addr = parse('"Jane Doe" <jane@example.com>')
        assert addr.display_name == "Jane Doe"

    def test_question_mark_in_atom(self) -> None:
        # "?" is legal atext, so the display name needs no quotes.
        addr = parse("Who? <one@y.test>")
        assert addr.display_name == "Who?"

    def test_phrase_joins_with_space(self) -> None:
        addr = parse("One Two Three <o@example.com>")
        assert addr.display_name == "One Two Three"


# ===========================================================================
# §3.4  address / mailbox / group / lists
# ===========================================================================


class TestAddress:
    def test_simple_addr_spec(self) -> None:
        addr = parse("user@example.com")
        assert (addr.display_name, addr.local_part, addr.domain) == (
            None,
            "user",
            "example.com",
        )
        assert addr.is_group is False
        assert addr.group_members == []
        assert addr.source == "user@example.com"

    def test_name_addr_quoted(self) -> None:
        addr = parse('"John Doe" <john@example.com>')
        assert addr.display_name == "John Doe"
        assert (addr.local_part, addr.domain) == ("john", "example.com")

    def test_name_addr_phrase(self) -> None:
        addr = parse("John Doe <jdoe@example.org>")
        assert addr.display_name == "John Doe"

    def test_angle_addr_without_display_name(self) -> None:
        addr = parse("<boss@nil.test>")
        assert addr.display_name is None
        assert (addr.local_part, addr.domain) == ("boss", "nil.test")

    def test_group(self) -> None:
        addr = parse("A Group:user1@a.com, user2@b.com;")
        assert addr.is_group is True
        assert addr.display_name == "A Group"
        assert [m.local_part for m in addr.group_members] == ["user1", "user2"]
        assert [m.domain for m in addr.group_members] == ["a.com", "b.com"]

    def test_group_members_have_display_names(self) -> None:
        addr = parse(
            "A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;"
        )
        members = addr.group_members
        assert [m.display_name for m in members] == ["Ed Jones", None, "John"]

    def test_empty_group(self) -> None:
        addr = parse("Undisclosed recipients:;")
        assert addr.is_group is True
        assert addr.display_name == "Undisclosed recipients"
        assert addr.group_members == []

    def test_group_list_of_cfws(self) -> None:
        # group-list = CFWS, i.e. a group with only a comment.
        addr = parse("Team:(comment);")
        assert addr.group_members == []
        assert addr.comments == ["comment"]

    def test_address_list(self) -> None:
        addrs = parse_list("a@b.com, c@d.com")
        assert [(a.local_part, a.domain) for a in addrs] == [
            ("a", "b.com"),
            ("c", "d.com"),
        ]

    def test_address_list_mixed_forms(self) -> None:
        addrs = parse_list('"X" <x@y.com>, plain@example.org')
        assert addrs[0].display_name == "X"
        assert addrs[1].display_name is None

    def test_address_list_from_appendix(self) -> None:
        addrs = parse_list("Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>")
        assert [(a.display_name, a.local_part, a.domain) for a in addrs] == [
            ("Mary Smith", "mary", "x.test"),
            (None, "jdoe", "example.org"),
            ("Who?", "one", "y.test"),
        ]

    def test_mailbox_list(self) -> None:
        mboxes = parse_mboxes("a@b.com, c@d.com")
        assert [(m.local_part, m.domain) for m in mboxes] == [
            ("a", "b.com"),
            ("c", "d.com"),
        ]

    def test_group_in_address_list(self) -> None:
        addrs = parse_list("A Group:user1@a.com, user2@b.com;, solo@x.test")
        assert addrs[0].is_group is True
        assert len(addrs[0].group_members) == 2
        assert addrs[1].local_part == "solo"

    def test_appendix_group_example(self) -> None:
        # Appendix A.1.3 with folding and comments (A.5).
        raw = (
            "A Group(Some people)\r\n"
            "     :Chris Jones <c@(Chris's host.)public.example>,\r\n"
            "         joe@example.org,\r\n"
            "      John <jdoe@one.test> (my dear friend); (the end of the group)"
        )
        addrs = parse_list(raw, strict=False)
        assert len(addrs) == 1
        group = addrs[0]
        assert group.is_group is True
        assert group.display_name == "A Group"
        assert [m.local_part for m in group.group_members] == ["c", "joe", "jdoe"]
        assert "Some people" in group.comments
        assert "the end of the group" in group.comments


# ===========================================================================
# §3.4.1  addr-spec / domain-literal
# ===========================================================================


class TestAddrSpecDomain:
    def test_simple_addr_spec(self) -> None:
        assert (parse("user@example.com").local_part, parse("user@example.com").domain) == (
            "user",
            "example.com",
        )

    def test_plus_tagging(self) -> None:
        addr = parse("user+tag@example.com")
        assert (addr.local_part, addr.domain) == ("user+tag", "example.com")

    def test_ipv4_domain_literal(self) -> None:
        addr = parse("user@[192.168.1.1]")
        assert addr.domain == "192.168.1.1"

    def test_ipv6_domain_literal(self) -> None:
        addr = parse("user@[IPv6:2001:db8::1]")
        assert addr.domain == "IPv6:2001:db8::1"

    def test_full_ipv6_domain_literal(self) -> None:
        addr = parse("postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]")
        assert addr.domain == "IPv6:2001:db8:85a3::8a2e:370:7334"

    def test_quoted_string_local_part(self) -> None:
        addr = parse('"quoted"@example.com')
        assert (addr.local_part, addr.domain) == ("quoted", "example.com")

    def test_multi_label_domain(self) -> None:
        addr = parse("user@sub.domain.example")
        assert addr.domain == "sub.domain.example"

    def test_fws_inside_domain_literal(self) -> None:
        # *([FWS] dtext): folding is permitted within the literal.
        addr = parse("user@[IPv6:2001:db8::\r\n 1]")
        assert addr.domain == "IPv6:2001:db8:: 1"

    def test_unterminated_domain_literal_rejected(self) -> None:
        rejects("user@[192.168.1.1")

    def test_backslash_in_domain_literal_strict_rejected(self) -> None:
        # dtext excludes "\"; only obs-dtext (permissive) allows it.
        rejects("user@[a\\]b]")
        addr = parse("user@[a\\]b]", strict=False)
        assert addr.domain == "a]b"


# ===========================================================================
# §4.4  obsolete addressing (permissive mode)
# ===========================================================================


class TestObsoleteAddressing:
    def test_obs_local_part_mixed(self) -> None:
        rejects('user."quoted"@example.com', strict=True)
        addr = parse('user."quoted"@example.com', strict=False)
        assert addr.local_part == "user.quoted"

    def test_obs_domain_leading_dot(self) -> None:
        rejects("user@.leading-dot.com", strict=True)
        addr = parse("user@.leading-dot.com", strict=False)
        assert addr.domain == ".leading-dot.com"

    def test_obs_domain_cfws_around_dots(self) -> None:
        addr = parse("jdoe@test  . example", strict=False)
        assert addr.domain == "test.example"

    def test_obs_phrase_with_period(self) -> None:
        rejects("Joe Q. Public <john.q.public@example.com>", strict=True)
        addr = parse("Joe Q. Public <john.q.public@example.com>", strict=False)
        assert addr.display_name == "Joe Q. Public"

    def test_obs_route_in_angle_addr(self) -> None:
        rejects("Mary Smith <@node.test:mary@example.net>", strict=True)
        addr = parse("Mary Smith <@node.test:mary@example.net>", strict=False)
        assert addr.display_name == "Mary Smith"
        assert (addr.local_part, addr.domain) == ("mary", "example.net")

    def test_obs_route_with_multiple_domains(self) -> None:
        addr = parse("user <@a.test,@b.test:user@final.test>", strict=False)
        assert (addr.local_part, addr.domain) == ("user", "final.test")

    def test_obs_addr_list_null_member(self) -> None:
        rejects("a@b.com, , c@d.com", strict=True)
        addrs = parse_list("a@b.com, , c@d.com", strict=False)
        assert [(a.local_part, a.domain) for a in addrs] == [
            ("a", "b.com"),
            ("c", "d.com"),
        ]

    def test_obs_addr_list_leading_and_trailing_commas(self) -> None:
        addrs = parse_list(",a@b.com,", strict=False)
        assert [(a.local_part, a.domain) for a in addrs] == [("a", "b.com")]

    def test_obs_group_list_commas(self) -> None:
        addr = parse("A Group: , , ;", strict=False)
        assert addr.is_group is True
        assert addr.group_members == []

    def test_obs_mbox_list_trailing_comma(self) -> None:
        rejects("A Group:user1@a.com,;", strict=True)
        addr = parse("A Group:user1@a.com,;", strict=False)
        assert [m.local_part for m in addr.group_members] == ["user1"]

    def test_appendix_obsolete_addressing(self) -> None:
        raw = "Mary Smith <@node.test:mary@example.net>, , jdoe@test  . example"
        addrs = parse_list(raw, strict=False)
        assert [(a.display_name, a.local_part, a.domain) for a in addrs] == [
            ("Mary Smith", "mary", "example.net"),
            (None, "jdoe", "test.example"),
        ]

    def test_obs_quoted_pair_in_comment(self) -> None:
        # obs-qp allows "\" followed by control characters (permissive).
        addr = parse("(a\\\x01b)user@example.com", strict=False)
        assert addr.comments == ["a\x01b"]


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_998_character_input(self) -> None:
        # RFC 5322 line length limit: inputs up to 998 chars must parse.
        local = "a" * 493
        domain = "b" * 500 + ".com"
        raw = f"{local}@{domain}"
        assert len(raw) == 998
        addr = parse(raw)
        assert addr.local_part == local
        assert addr.domain == domain

    def test_over_998_rejected_in_strict(self) -> None:
        raw = "a@" + "b" * 1000 + ".com"
        rejects(raw, strict=True)
        # Permissive mode still accepts (robustness).
        addr = parse(raw, strict=False)
        assert addr.domain == "b" * 1000 + ".com"

    def test_empty_quoted_local_part(self) -> None:
        addr = parse('""@example.com')
        assert addr.local_part == ""

    def test_deeply_nested_comments(self) -> None:
        addr = parse("((((deep))))user@example.com")
        assert len(addr.comments) == 4

    def test_source_field_preserved(self) -> None:
        raw = '"John Doe" <john@example.com>'
        assert parse(raw).source == raw

    def test_source_field_of_group_member(self) -> None:
        addr = parse("A Group:user1@a.com, user2@b.com;")
        assert addr.group_members[0].source == "user1@a.com"

    def test_whitespace_only_input_rejected(self) -> None:
        rejects("   ")
        rejects("")

    def test_leading_and_trailing_fws(self) -> None:
        addr = parse("  user@example.com  ")
        assert (addr.local_part, addr.domain) == ("user", "example.com")


# ===========================================================================
# Invalid / rejection cases
# ===========================================================================


class TestInvalid:
    def test_missing_domain(self) -> None:
        rejects("user@")

    def test_missing_local_part(self) -> None:
        rejects("@example.com")

    def test_double_at_sign(self) -> None:
        rejects("user@@example.com")

    def test_bare_at_sign(self) -> None:
        rejects("@")

    def test_unterminated_quoted_string(self) -> None:
        rejects('"unterminated@example.com')

    def test_trailing_garbage(self) -> None:
        rejects("user@example.com extra")

    def test_space_in_local_part_strict(self) -> None:
        # "user name@..." is not a valid addr-spec; obs forms would be
        # needed for display-name + address, which "<...>" is missing here.
        rejects("user name@example.com")

    def test_dot_atom_leading_dot_strict(self) -> None:
        rejects("user@.com")

    def test_domain_with_trailing_dot_strict(self) -> None:
        # dot-atom-text requires atext after every "."
        rejects("user@example.com.")

    def test_consecutive_dots_strict(self) -> None:
        rejects("user@example..com")

    def test_trailing_comma_strict(self) -> None:
        rejects("a@b.com,", strict=True)
        with pytest.raises(AddressParseError):
            AddressParser(strict=True).parse_address_list("a@b.com,")

    def test_control_char_outside_quotes_strict(self) -> None:
        rejects("\x01user@example.com")

    def test_group_without_semicolon(self) -> None:
        rejects("A Group:user1@a.com")

    def test_group_without_colon(self) -> None:
        rejects("A Group user1@a.com;")

    def test_mailbox_list_with_group_rejected(self) -> None:
        # parse_mailbox_list only accepts mailboxes, not groups.
        with pytest.raises(AddressParseError):
            AddressParser().parse_mailbox_list("A Group:user1@a.com;")