from __future__ import annotations

import unittest

from parser import AddressParser, RFC5322Address


def parse(raw: str, *, strict: bool = True) -> RFC5322Address:
    return AddressParser(strict=strict).parse(raw)


def assert_mailbox(
    test_case: unittest.TestCase,
    value: RFC5322Address,
    *,
    display_name: str | None,
    local_part: str | None,
    domain: str | None,
) -> None:
    test_case.assertFalse(value.is_group)
    test_case.assertEqual(value.display_name, display_name)
    test_case.assertEqual(value.local_part, local_part)
    test_case.assertEqual(value.domain, domain)


def assert_group(
    test_case: unittest.TestCase,
    value: RFC5322Address,
    *,
    display_name: str,
    member_count: int,
) -> None:
    test_case.assertTrue(value.is_group)
    test_case.assertEqual(value.display_name, display_name)
    test_case.assertIsNone(value.local_part)
    test_case.assertIsNone(value.domain)
    test_case.assertEqual(len(value.group_members), member_count)


class Test321QuotedPair(unittest.TestCase):
    def test_quoted_pair_in_quoted_string_escaped_double_quote(self) -> None:
        value = parse('"ab\\"cd"@example.com')
        assert_mailbox(self, value, display_name=None, local_part='ab"cd', domain="example.com")

    def test_quoted_pair_in_quoted_string_escaped_backslash(self) -> None:
        value = parse('"ab\\\\cd"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="ab\\cd", domain="example.com")

    def test_quoted_pair_in_quoted_string_escaped_at_sign(self) -> None:
        value = parse('"ab\\@cd"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="ab@cd", domain="example.com")

    def test_quoted_pair_in_quoted_string_escaped_space(self) -> None:
        value = parse('"a\\ b"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="a b", domain="example.com")

    def test_quoted_pair_in_comment(self) -> None:
        value = parse(r"John (A nice \) chap) <john@example.com>")
        assert_mailbox(self, value, display_name="John", local_part="john", domain="example.com")
        self.assertTrue(any(")" in comment for comment in value.comments))


class Test322FWS(unittest.TestCase):
    def test_fws_single_spaces_in_display_name(self) -> None:
        value = parse("John Doe <john@example.com>")
        assert_mailbox(self, value, display_name="John Doe", local_part="john", domain="example.com")

    def test_fws_tab_in_display_name(self) -> None:
        value = parse("John\tDoe <john@example.com>")
        assert_mailbox(self, value, display_name="John Doe", local_part="john", domain="example.com")

    def test_fws_crlf_in_display_name(self) -> None:
        value = parse("John\r\n Doe <john@example.com>")
        assert_mailbox(self, value, display_name="John Doe", local_part="john", domain="example.com")

    def test_fws_in_quoted_string_local_part(self) -> None:
        value = parse('"John\r\n Doe"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="John Doe", domain="example.com")

    def test_fws_in_address_list(self) -> None:
        items = AddressParser().parse_address_list("A <a@b>,\r\n B <c@d>")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name="A", local_part="a", domain="b")
        assert_mailbox(self, items[1], display_name="B", local_part="c", domain="d")


class Test323CFWSComments(unittest.TestCase):
    def test_leading_and_trailing_comments_around_addr_spec(self) -> None:
        value = parse("(lead)user@example.com(trail)")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="example.com")
        self.assertTrue(any("lead" in comment for comment in value.comments))
        self.assertTrue(any("trail" in comment for comment in value.comments))

    def test_comments_between_display_name_words(self) -> None:
        value = parse("John (a) Doe <john@example.com>")
        assert_mailbox(self, value, display_name="John Doe", local_part="john", domain="example.com")
        self.assertTrue(any(comment == "a" for comment in value.comments))

    def test_nested_comment_text_collected(self) -> None:
        value = parse("John (outer (inner) outer) <john@example.com>")
        assert_mailbox(self, value, display_name="John", local_part="john", domain="example.com")
        self.assertTrue(any("inner" in comment for comment in value.comments))

    def test_comments_before_angle_addr(self) -> None:
        value = parse("(lead) <john@example.com>")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="example.com")
        self.assertTrue(any("lead" in comment for comment in value.comments))

    def test_comments_around_at_sign(self) -> None:
        value = parse("user (x) @ example.com")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="example.com")
        self.assertTrue(any(comment == "x" for comment in value.comments))

    def test_comments_on_domain_side(self) -> None:
        value = parse("user @ (x) example.com")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="example.com")
        self.assertTrue(any(comment == "x" for comment in value.comments))

    def test_comments_in_group_name(self) -> None:
        value = parse("Group (team): member@example.com;")
        assert_group(self, value, display_name="Group", member_count=1)
        self.assertTrue(any("team" in comment for comment in value.comments))

    def test_comments_in_address_list_items(self) -> None:
        items = AddressParser().parse_address_list("(x) A <a@b>, (y) B <c@d> (z)")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name="A", local_part="a", domain="b")
        assert_mailbox(self, items[1], display_name="B", local_part="c", domain="d")
        self.assertTrue(any(comment == "x" for comment in items[0].comments))
        self.assertTrue(any(comment == "y" for comment in items[1].comments))
        self.assertTrue(any("z" in comment for comment in items[1].comments))


class Test324QuotedString(unittest.TestCase):
    def test_quoted_string_empty_local_part(self) -> None:
        value = parse('""@example.com')
        assert_mailbox(self, value, display_name=None, local_part="", domain="example.com")

    def test_quoted_string_with_spaces(self) -> None:
        value = parse('"a b"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="a b", domain="example.com")

    def test_quoted_string_with_escaped_quote(self) -> None:
        value = parse('"a\\"b"@example.com')
        assert_mailbox(self, value, display_name=None, local_part='a"b', domain="example.com")

    def test_quoted_string_with_escaped_backslash(self) -> None:
        value = parse('"a\\\\b"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="a\\b", domain="example.com")

    def test_quoted_string_with_folded_whitespace(self) -> None:
        value = parse('"a\r\n b"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="a b", domain="example.com")

    def test_quoted_string_with_escaped_comma(self) -> None:
        value = parse('"x\\,y"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="x,y", domain="example.com")

    def test_quoted_string_as_display_name(self) -> None:
        value = parse('"Display Name" <user@example.com>')
        assert_mailbox(self, value, display_name="Display Name", local_part="user", domain="example.com")

    def test_quoted_string_with_punctuation_chars(self) -> None:
        value = parse('"a.b,c;d"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="a.b,c;d", domain="example.com")


class Test325MiscTokens(unittest.TestCase):
    def test_atom_local_part_with_plus(self) -> None:
        value = parse("user+tag@example.com")
        assert_mailbox(self, value, display_name=None, local_part="user+tag", domain="example.com")

    def test_dot_atom_domain_with_multiple_labels(self) -> None:
        value = parse("user@sub.example.co.uk")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="sub.example.co.uk")

    def test_phrase_with_atoms_and_quoted_word(self) -> None:
        value = parse('"Jane Q" Public <jane@example.com>')
        assert_mailbox(self, value, display_name="Jane Q Public", local_part="jane", domain="example.com")


class Test34AddressMailboxGroup(unittest.TestCase):
    def test_addr_spec_only_mailbox(self) -> None:
        value = parse("john@example.com")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="example.com")

    def test_name_addr_with_display_name(self) -> None:
        value = parse("John Doe <john@example.com>")
        assert_mailbox(self, value, display_name="John Doe", local_part="john", domain="example.com")

    def test_angle_addr_without_display_name(self) -> None:
        value = parse("<john@example.com>")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="example.com")

    def test_mailbox_list_two_items(self) -> None:
        items = AddressParser().parse_mailbox_list("john@example.com, jane@example.com")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name=None, local_part="john", domain="example.com")
        assert_mailbox(self, items[1], display_name=None, local_part="jane", domain="example.com")

    def test_address_list_two_name_addrs(self) -> None:
        items = AddressParser().parse_address_list("John <j@a>, Jane <j@b>")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name="John", local_part="j", domain="a")
        assert_mailbox(self, items[1], display_name="Jane", local_part="j", domain="b")

    def test_group_with_two_members(self) -> None:
        value = parse("Group: john@example.com, jane@example.com;")
        assert_group(self, value, display_name="Group", member_count=2)
        assert_mailbox(self, value.group_members[0], display_name=None, local_part="john", domain="example.com")
        assert_mailbox(self, value.group_members[1], display_name=None, local_part="jane", domain="example.com")

    def test_empty_group(self) -> None:
        value = parse("Group:;")
        assert_group(self, value, display_name="Group", member_count=0)

    def test_group_with_comment_only_members(self) -> None:
        value = parse("Group:(nobody);")
        assert_group(self, value, display_name="Group", member_count=0)
        self.assertTrue(any("nobody" in comment for comment in value.comments))

    def test_group_in_address_list(self) -> None:
        items = AddressParser().parse_address_list("Group: a@b; , c@d")
        self.assertEqual(len(items), 2)
        assert_group(self, items[0], display_name="Group", member_count=1)
        assert_mailbox(self, items[1], display_name=None, local_part="c", domain="d")

    def test_mailbox_with_leading_cfws(self) -> None:
        value = parse("(x) John <j@a>")
        assert_mailbox(self, value, display_name="John", local_part="j", domain="a")
        self.assertTrue(any("x" in comment for comment in value.comments))

    def test_mailbox_with_trailing_cfws(self) -> None:
        value = parse("John <j@a> (y)")
        assert_mailbox(self, value, display_name="John", local_part="j", domain="a")
        self.assertTrue(any("y" in comment for comment in value.comments))

    def test_address_list_with_comment_wrapped_items(self) -> None:
        items = AddressParser().parse_address_list("(x) John <j@a>, (y) Jane <j@b>")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name="John", local_part="j", domain="a")
        assert_mailbox(self, items[1], display_name="Jane", local_part="j", domain="b")
        self.assertTrue(any("x" in comment for comment in items[0].comments))
        self.assertTrue(any("y" in comment for comment in items[1].comments))


class Test341AddrSpecDomainLiteral(unittest.TestCase):
    def test_simple_dot_atom_addr_spec(self) -> None:
        value = parse("john.doe@example.com")
        assert_mailbox(self, value, display_name=None, local_part="john.doe", domain="example.com")

    def test_quoted_local_part_addr_spec(self) -> None:
        value = parse('"john.doe"@example.com')
        assert_mailbox(self, value, display_name=None, local_part="john.doe", domain="example.com")

    def test_ipv4_domain_literal(self) -> None:
        value = parse("john@[127.0.0.1]")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="127.0.0.1")

    def test_ipv6_domain_literal(self) -> None:
        value = parse("john@[IPv6:2001:db8::1]")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="IPv6:2001:db8::1")

    def test_domain_literal_with_plain_text(self) -> None:
        value = parse("john@[example-host]")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="example-host")

    def test_domain_literal_with_dtext_punctuation(self) -> None:
        value = parse("john@[abc!^xyz]")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="abc!^xyz")

    def test_domain_literal_with_cfws(self) -> None:
        value = parse("user @ [example-host]")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="example-host")

    def test_mailbox_list_with_domain_literals(self) -> None:
        items = AddressParser().parse_mailbox_list("john@[192.0.2.1], jane@[IPv6:2001:db8::2]")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name=None, local_part="john", domain="192.0.2.1")
        assert_mailbox(self, items[1], display_name=None, local_part="jane", domain="IPv6:2001:db8::2")


class Test44Obsolete(unittest.TestCase):
    def test_obs_local_part_with_quoted_word(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("a.\"b\".c@example.com")
        assert_mailbox(self, value, display_name=None, local_part="a.b.c", domain="example.com")

    def test_obs_local_part_with_cfws(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("john . doe@example.com")
        assert_mailbox(self, value, display_name=None, local_part="john.doe", domain="example.com")

    def test_obs_domain_with_cfws(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("john@example . com")
        assert_mailbox(self, value, display_name=None, local_part="john", domain="example.com")

    def test_obs_angle_addr_with_route(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("John <@a,@b:user@example.com>")
        assert_mailbox(self, value, display_name="John", local_part="user", domain="example.com")

    def test_obs_angle_addr_without_display_name(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("<@a:user@example.com>")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="example.com")

    def test_obs_group_list_only_commas(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("List: , , ;")
        assert_group(self, value, display_name="List", member_count=0)

    def test_obs_mailbox_list_with_leading_commas(self) -> None:
        parser = AddressParser(strict=False)
        items = parser.parse_mailbox_list(",,john@example.com,,")
        self.assertEqual(len(items), 1)
        assert_mailbox(self, items[0], display_name=None, local_part="john", domain="example.com")

    def test_obs_mailbox_list_with_trailing_commas(self) -> None:
        parser = AddressParser(strict=False)
        items = parser.parse_mailbox_list("john@example.com,,")
        self.assertEqual(len(items), 1)
        assert_mailbox(self, items[0], display_name=None, local_part="john", domain="example.com")

    def test_obs_address_list_with_route_and_mailbox(self) -> None:
        parser = AddressParser(strict=False)
        items = parser.parse_address_list("John <@a:user@example.com>, jane@example.com")
        self.assertEqual(len(items), 2)
        assert_mailbox(self, items[0], display_name="John", local_part="user", domain="example.com")
        assert_mailbox(self, items[1], display_name=None, local_part="jane", domain="example.com")

    def test_obs_group_list_with_comments(self) -> None:
        parser = AddressParser(strict=False)
        value = parser.parse("List:(x), , ;")
        assert_group(self, value, display_name="List", member_count=0)
        self.assertTrue(any("x" in comment for comment in value.comments))


class TestEdgeCases(unittest.TestCase):
    def test_exact_998_character_input(self) -> None:
        local = "a" * 993
        raw = f"{local}@x.co"
        self.assertEqual(len(raw), 998)
        value = parse(raw)
        assert_mailbox(self, value, display_name=None, local_part=local, domain="x.co")

    def test_empty_quoted_string_local_part(self) -> None:
        value = parse('""@example.com')
        assert_mailbox(self, value, display_name=None, local_part="", domain="example.com")

    def test_empty_domain_literal(self) -> None:
        value = parse("user@[]")
        assert_mailbox(self, value, display_name=None, local_part="user", domain="")

    def test_source_is_preserved_on_parsed_address(self) -> None:
        raw = "John <john@example.com>"
        value = parse(raw)
        self.assertEqual(value.source, raw)

    def test_permissive_empty_address_list_from_cfws_only_input(self) -> None:
        items = AddressParser(strict=False).parse_address_list("")
        self.assertEqual(items, [])


class TestInvalidRejection(unittest.TestCase):
    def test_reject_empty_input(self) -> None:
        with self.assertRaises(ValueError):
            parse("")

    def test_reject_trailing_content(self) -> None:
        with self.assertRaises(ValueError):
            parse("john@example.com extra")

    def test_reject_double_at(self) -> None:
        with self.assertRaises(ValueError):
            parse("john@@example.com")

    def test_reject_missing_domain(self) -> None:
        with self.assertRaises(ValueError):
            parse("john@")

    def test_reject_missing_local_part(self) -> None:
        with self.assertRaises(ValueError):
            parse("@example.com")

    def test_reject_unterminated_quoted_string(self) -> None:
        with self.assertRaises(ValueError):
            parse('"unterminated@example.com')

    def test_reject_unterminated_comment(self) -> None:
        with self.assertRaises(ValueError):
            parse("(unterminated")

    def test_reject_group_missing_semicolon(self) -> None:
        with self.assertRaises(ValueError):
            parse("Group:john@example.com")

    def test_reject_obsolete_local_part_in_strict_mode(self) -> None:
        with self.assertRaises(ValueError):
            parse("john . doe@example.com")

    def test_reject_obsolete_domain_in_strict_mode(self) -> None:
        with self.assertRaises(ValueError):
            parse("john@example . com")

    def test_reject_obsolete_route_in_strict_mode(self) -> None:
        with self.assertRaises(ValueError):
            parse("John <@a,@b:user@example.com>")


if __name__ == "__main__":
    unittest.main()
