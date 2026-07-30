"""Test suite for RFC 5322 AddressParser — organized by RFC section."""

from __future__ import annotations

import unittest

from parser import AddressParser, ParseError, RFC5322Address


class TestQuotedPair_3_2_1(unittest.TestCase):
    """§3.2.1 quoted-pair — at least 5 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_escaped_quote_in_local(self) -> None:
        r = self.p.parse(r'"quoted\"string"@example.com')
        self.assertEqual(r.local_part, 'quoted"string')

    def test_escaped_backslash(self) -> None:
        r = self.p.parse(r'"a\\b"@example.com')
        self.assertEqual(r.local_part, r"a\b")

    def test_escaped_space(self) -> None:
        r = self.p.parse(r'"a\ b"@example.com')
        self.assertEqual(r.local_part, "a b")

    def test_escaped_specials_in_quoted(self) -> None:
        r = self.p.parse(r'"very.(),:;<>\"@[]\\ long"@example.com')
        self.assertEqual(r.local_part, r'very.(),:;<>"@[]\ long')

    def test_escaped_at_in_quoted(self) -> None:
        r = self.p.parse(r'"user\@name"@example.com')
        self.assertEqual(r.local_part, "user@name")

    def test_quoted_pair_in_comment(self) -> None:
        r = self.p.parse(r'(c\(x\))user@example.com')
        self.assertEqual(r.local_part, "user")
        self.assertIn("c(x)", r.comments)


class TestFWS_3_2_2(unittest.TestCase):
    """§3.2.2 FWS — at least 5 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_space_around_angle(self) -> None:
        r = self.p.parse(" <user@example.com> ")
        self.assertEqual(r.local_part, "user")
        self.assertEqual(r.domain, "example.com")

    def test_tab_cfws(self) -> None:
        r = self.p.parse("\tuser@example.com\t")
        self.assertEqual(r.local_part, "user")

    def test_fws_in_quoted_string(self) -> None:
        r = self.p.parse('"hello world"@example.com')
        self.assertEqual(r.local_part, "hello world")

    def test_folded_fws_in_quoted(self) -> None:
        r = self.p.parse('"hello\r\n world"@example.com')
        self.assertEqual(r.local_part, "hello world")

    def test_fws_before_domain_literal(self) -> None:
        r = self.p.parse("user@ [192.168.0.1]")
        self.assertEqual(r.domain, "[192.168.0.1]")

    def test_multiple_spaces_as_cfws(self) -> None:
        r = self.p.parse("user  @  example.com")
        self.assertEqual(r.local_part, "user")
        self.assertEqual(r.domain, "example.com")


class TestCFWSComments_3_2_3(unittest.TestCase):
    """§3.2.3 CFWS/comments — at least 8 cases.
    Note: §3.2.2 defines CFWS; §3.2.3 is Atom — comments live in CFWS (§3.2.2).
    Tests cover CFWS/comment behavior used throughout address parsing.
    """

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_leading_comment(self) -> None:
        r = self.p.parse("(hi)user@example.com")
        self.assertEqual(r.comments, ["hi"])
        self.assertEqual(r.local_part, "user")

    def test_trailing_comment(self) -> None:
        r = self.p.parse("user@example.com(bye)")
        self.assertIn("bye", r.comments)

    def test_mid_comments(self) -> None:
        r = self.p.parse("(comment)user(mid)@(end)example.com")
        self.assertEqual(r.comments, ["comment", "mid", "end"])
        self.assertEqual(r.local_part, "user")
        self.assertEqual(r.domain, "example.com")

    def test_nested_comments(self) -> None:
        r = self.p.parse("(outer(inner))user@example.com")
        self.assertTrue(any("inner" in c for c in r.comments))

    def test_comment_with_spaces(self) -> None:
        r = self.p.parse("( a comment )user@example.com")
        self.assertEqual(r.local_part, "user")
        self.assertTrue(len(r.comments) >= 1)

    def test_empty_comment(self) -> None:
        r = self.p.parse("()user@example.com")
        self.assertIn("", r.comments)

    def test_comment_around_angle_addr(self) -> None:
        r = self.p.parse("(n)<user@example.com>(t)")
        self.assertEqual(r.local_part, "user")
        self.assertIn("n", r.comments)
        self.assertIn("t", r.comments)

    def test_cfws_stripped_from_addr_spec(self) -> None:
        r = self.p.parse("(x)user(y)@example.com")
        self.assertEqual(r.local_part, "user")
        self.assertNotIn("(", r.local_part)


class TestQuotedString_3_2_4(unittest.TestCase):
    """§3.2.4 quoted-string — at least 8 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_simple_quoted_local(self) -> None:
        r = self.p.parse('"user"@example.com')
        self.assertEqual(r.local_part, "user")

    def test_space_only_quoted(self) -> None:
        r = self.p.parse('" "@example.com')
        self.assertEqual(r.local_part, " ")

    def test_empty_quoted(self) -> None:
        r = self.p.parse('""@example.com')
        self.assertEqual(r.local_part, "")

    def test_specials_in_quoted(self) -> None:
        r = self.p.parse('"()<>[]:,;@\\\\"@example.com')
        self.assertIn("(", r.local_part)

    def test_display_name_quoted(self) -> None:
        r = self.p.parse('"John Doe" <john@example.com>')
        self.assertEqual(r.display_name, "John Doe")
        self.assertEqual(r.local_part, "john")

    def test_quoted_with_dots(self) -> None:
        r = self.p.parse('"john.doe"@example.com')
        self.assertEqual(r.local_part, "john.doe")

    def test_quoted_with_plus(self) -> None:
        r = self.p.parse('"a+b=c"@example.com')
        self.assertEqual(r.local_part, "a+b=c")

    def test_quoted_pair_and_qtext_mix(self) -> None:
        r = self.p.parse(r'"ab\"cd"@example.com')
        self.assertEqual(r.local_part, 'ab"cd')


class TestMiscTokens_3_2_5(unittest.TestCase):
    """§3.2.5 miscellaneous tokens (word/phrase) — at least 3 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_phrase_atom_display(self) -> None:
        r = self.p.parse("John <john@example.com>")
        self.assertEqual(r.display_name, "John")

    def test_phrase_multi_word(self) -> None:
        r = self.p.parse("John Doe <john@example.com>")
        self.assertEqual(r.display_name, "John Doe")

    def test_phrase_mixed_atom_quoted(self) -> None:
        r = self.p.parse('John "The Boss" Doe <john@example.com>')
        self.assertEqual(r.display_name, "John The Boss Doe")


class TestAddressMailboxGroup_3_4(unittest.TestCase):
    """§3.4 address/mailbox/group — at least 12 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_simple_addr_spec(self) -> None:
        r = self.p.parse("user@example.com")
        self.assertFalse(r.is_group)
        self.assertEqual(r.local_part, "user")
        self.assertEqual(r.domain, "example.com")
        self.assertIsNone(r.display_name)

    def test_name_addr(self) -> None:
        r = self.p.parse("Alice <alice@example.com>")
        self.assertEqual(r.display_name, "Alice")
        self.assertEqual(r.local_part, "alice")

    def test_angle_addr_only(self) -> None:
        r = self.p.parse("<bob@example.com>")
        self.assertEqual(r.local_part, "bob")
        self.assertIsNone(r.display_name)

    def test_group_two_members(self) -> None:
        r = self.p.parse("A Group:user1@a.com, user2@b.com;")
        self.assertTrue(r.is_group)
        self.assertEqual(r.display_name, "A Group")
        self.assertEqual(len(r.group_members), 2)
        self.assertEqual(r.group_members[0].local_part, "user1")
        self.assertEqual(r.group_members[1].domain, "b.com")

    def test_group_empty(self) -> None:
        r = self.p.parse("Empty:;")
        self.assertTrue(r.is_group)
        self.assertEqual(r.group_members, [])

    def test_group_one_member(self) -> None:
        r = self.p.parse("Solo: only@x.com;")
        self.assertEqual(len(r.group_members), 1)

    def test_mailbox_list_two(self) -> None:
        items = self.p.parse_mailbox_list("a@b.com, c@d.com")
        self.assertEqual(len(items), 2)

    def test_address_list_mixed(self) -> None:
        items = self.p.parse_address_list(
            "a@b.com, Team: x@y.com;, c@d.com"
        )
        self.assertEqual(len(items), 3)
        self.assertTrue(items[1].is_group)

    def test_source_preserved(self) -> None:
        raw = "user@example.com"
        r = self.p.parse(raw)
        self.assertEqual(r.source, raw)

    def test_plus_tag_local(self) -> None:
        r = self.p.parse("user+tag@example.com")
        self.assertEqual(r.local_part, "user+tag")

    def test_dot_atom_local(self) -> None:
        r = self.p.parse("first.last@example.com")
        self.assertEqual(r.local_part, "first.last")

    def test_display_name_with_angle(self) -> None:
        r = self.p.parse('"J. Smith" <j.smith@example.com>')
        self.assertEqual(r.display_name, "J. Smith")
        self.assertEqual(r.local_part, "j.smith")


class TestAddrSpecDomainLiteral_3_4_1(unittest.TestCase):
    """§3.4.1 addr-spec / domain-literal — at least 8 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_ipv4_literal(self) -> None:
        r = self.p.parse("user+tag@[192.168.1.1]")
        self.assertEqual(r.domain, "[192.168.1.1]")

    def test_ipv6_short(self) -> None:
        r = self.p.parse("user@[IPv6:2001:db8::1]")
        self.assertEqual(r.domain, "[IPv6:2001:db8::1]")

    def test_ipv6_full(self) -> None:
        r = self.p.parse("postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]")
        self.assertEqual(r.domain, "[IPv6:2001:db8:85a3::8a2e:370:7334]")

    def test_dot_atom_domain(self) -> None:
        r = self.p.parse("a@mail.example.co.uk")
        self.assertEqual(r.domain, "mail.example.co.uk")

    def test_atext_specials_in_local(self) -> None:
        r = self.p.parse("user!name@example.com")
        self.assertEqual(r.local_part, "user!name")

    def test_domain_literal_with_fws(self) -> None:
        r = self.p.parse("u@[ 127.0.0.1 ]")
        self.assertEqual(r.domain, "[127.0.0.1]")

    def test_simple_local_domain(self) -> None:
        r = self.p.parse("postmaster@example.com")
        self.assertEqual(r.local_part, "postmaster")

    def test_percent_in_local(self) -> None:
        r = self.p.parse("user%host@example.com")
        self.assertEqual(r.local_part, "user%host")


class TestObsolete_4_4(unittest.TestCase):
    """§4.4 obsolete addressing — at least 8 cases."""

    def test_obs_local_mixed_strict_rejects(self) -> None:
        p = AddressParser(strict=True)
        with self.assertRaises(ParseError):
            p.parse('user."quoted"@example.com')

    def test_obs_local_mixed_permissive(self) -> None:
        p = AddressParser(strict=False)
        r = p.parse('user."quoted"@example.com')
        self.assertEqual(r.local_part, "user.quoted")

    def test_obs_domain_leading_dot_strict_rejects(self) -> None:
        p = AddressParser(strict=True)
        with self.assertRaises(ParseError):
            p.parse("user@.leading-dot.com")

    def test_obs_domain_leading_dot_permissive(self) -> None:
        p = AddressParser(strict=False)
        r = p.parse("user@.leading-dot.com")
        self.assertEqual(r.domain, ".leading-dot.com")

    def test_obs_route_permissive(self) -> None:
        p = AddressParser(strict=False)
        r = p.parse("<@gateway:user@example.com>")
        self.assertEqual(r.local_part, "user")
        self.assertEqual(r.domain, "example.com")

    def test_obs_route_strict_rejects(self) -> None:
        p = AddressParser(strict=True)
        with self.assertRaises(ParseError):
            p.parse("<@gateway:user@example.com>")

    def test_obs_mbox_list_null_members(self) -> None:
        p = AddressParser(strict=False)
        items = p.parse_mailbox_list("a@b.com,,c@d.com")
        self.assertEqual(len(items), 2)

    def test_obs_mbox_list_null_strict_rejects(self) -> None:
        p = AddressParser(strict=True)
        with self.assertRaises(ParseError):
            p.parse_mailbox_list("a@b.com,,c@d.com")

    def test_obs_quoted_then_atom(self) -> None:
        p = AddressParser(strict=False)
        r = p.parse('"foo".bar@example.com')
        self.assertEqual(r.local_part, "foo.bar")


class TestEdgeCases(unittest.TestCase):
    """Edge cases — at least 5 cases."""

    def test_max_length_998(self) -> None:
        local = "a" * 50
        domain = "b" * (998 - len(local) - 1)
        raw = f"{local}@{domain}"
        self.assertEqual(len(raw), 998)
        r = AddressParser().parse(raw)
        self.assertEqual(r.local_part, local)

    def test_over_max_length_rejected(self) -> None:
        raw = "a@" + ("b" * 997)
        self.assertGreater(len(raw), 998)
        with self.assertRaises(ParseError):
            AddressParser().parse(raw)

    def test_empty_quoted_local(self) -> None:
        r = AddressParser().parse('""@example.com')
        self.assertEqual(r.local_part, "")

    def test_deeply_nested_comments(self) -> None:
        r = AddressParser().parse("(((n)))user@example.com")
        self.assertEqual(r.local_part, "user")
        self.assertTrue(len(r.comments) >= 1)

    def test_group_source(self) -> None:
        raw = "G: a@b.com;"
        r = AddressParser().parse(raw)
        self.assertEqual(r.source, raw)
        self.assertTrue(r.is_group)


class TestInvalidRejection(unittest.TestCase):
    """Invalid/rejection cases — at least 8 cases."""

    def setUp(self) -> None:
        self.p = AddressParser(strict=True)

    def test_missing_at(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("userexample.com")

    def test_missing_domain(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("user@")

    def test_missing_local(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("@example.com")

    def test_unclosed_quote(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse('"user@example.com')

    def test_unclosed_angle(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("<user@example.com")

    def test_unclosed_comment(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("(comment user@example.com")

    def test_unclosed_domain_literal(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("user@[192.168.1.1")

    def test_double_at(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("user@@example.com")

    def test_trailing_garbage(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("user@example.com extra")

    def test_bare_text(self) -> None:
        with self.assertRaises(ParseError):
            self.p.parse("not-an-address")


class TestAPITypes(unittest.TestCase):
    """Public API shape and type hints surface."""

    def test_rfc5322_address_fields(self) -> None:
        r = AddressParser().parse("a@b.com")
        self.assertIsInstance(r, RFC5322Address)
        self.assertIsInstance(r.group_members, list)
        self.assertIsInstance(r.comments, list)
        self.assertIsInstance(r.source, str)

    def test_strict_default(self) -> None:
        p = AddressParser()
        self.assertTrue(p.strict)


if __name__ == "__main__":
    unittest.main()
