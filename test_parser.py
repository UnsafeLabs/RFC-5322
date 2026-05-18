import unittest

from parser import AddressParser, RFC5322Address, RFC5322ParseError


class ParserAssertions:
    def strict(self) -> AddressParser:
        return AddressParser(strict=True)

    def permissive(self) -> AddressParser:
        return AddressParser(strict=False)

    def assert_rejects(self, raw: str, *, strict: bool = True) -> None:
        with self.assertRaises(RFC5322ParseError):
            AddressParser(strict=strict).parse(raw)


class TestQuotedPair321(ParserAssertions, unittest.TestCase):
    def test_escaped_quote_in_local_part(self) -> None:
        self.assertEqual(self.strict().parse('"quo\\"te"@example.com').local_part, 'quo"te')

    def test_escaped_backslash_in_local_part(self) -> None:
        self.assertEqual(self.strict().parse('"a\\\\b"@example.com').local_part, "a\\b")

    def test_escaped_space_in_quoted_string(self) -> None:
        self.assertEqual(self.strict().parse('"a\\ b"@example.com').local_part, "a b")

    def test_escaped_parenthesis_in_comment(self) -> None:
        parsed = self.strict().parse('(a\\)b)user@example.com')
        self.assertEqual(parsed.comments, ["a)b"])

    def test_rejects_strict_escaped_control(self) -> None:
        self.assert_rejects('"bad\\\x01"@example.com')


class TestFWS322(ParserAssertions, unittest.TestCase):
    def test_folding_whitespace_before_address(self) -> None:
        self.assertEqual(self.strict().parse(" \t user@example.com").local_part, "user")

    def test_folding_whitespace_after_address(self) -> None:
        self.assertEqual(self.strict().parse("user@example.com\r\n \t").domain, "example.com")

    def test_folding_whitespace_inside_quoted_string(self) -> None:
        self.assertEqual(self.strict().parse('"a\r\n b"@example.com').local_part, "a b")

    def test_folding_whitespace_around_angle_address(self) -> None:
        parsed = self.strict().parse("John\r\n \tDoe <john@example.com>")
        self.assertEqual(parsed.display_name, "John Doe")

    def test_rejects_bare_crlf_without_following_wsp(self) -> None:
        self.assert_rejects("user@example.com\r\nnext")


class TestCFWSAndComments323(ParserAssertions, unittest.TestCase):
    def test_comment_before_local_part(self) -> None:
        self.assertEqual(self.strict().parse("(lead)user@example.com").comments, ["lead"])

    def test_comment_between_local_part_and_at(self) -> None:
        parsed = self.strict().parse("user(comment)@example.com")
        self.assertEqual(parsed.comments, ["comment"])

    def test_comment_before_domain(self) -> None:
        parsed = self.strict().parse("user@(domain)example.com")
        self.assertEqual(parsed.comments, ["domain"])

    def test_nested_comments(self) -> None:
        parsed = self.strict().parse("(outer(inner))user@example.com")
        self.assertEqual(parsed.comments, ["outerinner"])

    def test_multiple_comments_preserve_order(self) -> None:
        parsed = self.strict().parse("(a)user(b)@(c)example.com(d)")
        self.assertEqual(parsed.comments, ["a", "b", "c", "d"])

    def test_comment_in_display_name_cfws(self) -> None:
        parsed = self.strict().parse("John (middle) Doe <john@example.com>")
        self.assertEqual(parsed.display_name, "John Doe")
        self.assertEqual(parsed.comments, ["middle"])

    def test_escaped_backslash_in_comment(self) -> None:
        parsed = self.strict().parse("(a\\\\b)user@example.com")
        self.assertEqual(parsed.comments, ["a\\b"])

    def test_rejects_unclosed_comment(self) -> None:
        self.assert_rejects("(unterminated user@example.com")


class TestQuotedString324(ParserAssertions, unittest.TestCase):
    def test_simple_quoted_local_part(self) -> None:
        self.assertEqual(self.strict().parse('"john doe"@example.com').local_part, "john doe")

    def test_empty_quoted_local_part(self) -> None:
        self.assertEqual(self.strict().parse('""@example.com').local_part, "")

    def test_space_only_quoted_local_part(self) -> None:
        self.assertEqual(self.strict().parse('" "@example.com').local_part, " ")

    def test_all_specials_inside_quoted_string(self) -> None:
        parsed = self.strict().parse('"very.(),:;<>\\"@[]\\\\ long"@example.com')
        self.assertEqual(parsed.local_part, 'very.(),:;<>"@[]\\ long')

    def test_quoted_display_name(self) -> None:
        parsed = self.strict().parse('"Doe, John" <john@example.com>')
        self.assertEqual(parsed.display_name, "Doe, John")

    def test_cfws_around_quoted_string(self) -> None:
        parsed = self.strict().parse('(c)"john"@example.com')
        self.assertEqual(parsed.local_part, "john")
        self.assertEqual(parsed.comments, ["c"])

    def test_rejects_unclosed_quote(self) -> None:
        self.assert_rejects('"john@example.com')

    def test_rejects_unescaped_quote_content(self) -> None:
        self.assert_rejects('"bad"quote"@example.com')


class TestMiscTokens325(ParserAssertions, unittest.TestCase):
    def test_atom_with_allowed_atext_symbols(self) -> None:
        parsed = self.strict().parse("user+tag!x@example.com")
        self.assertEqual(parsed.local_part, "user+tag!x")

    def test_dot_atom_domain(self) -> None:
        parsed = self.strict().parse("user@sub.example.com")
        self.assertEqual(parsed.domain, "sub.example.com")

    def test_phrase_combines_words(self) -> None:
        parsed = self.strict().parse("John Q Public <john@example.com>")
        self.assertEqual(parsed.display_name, "John Q Public")


class TestAddressSpecification34(ParserAssertions, unittest.TestCase):
    def test_simple_addr_spec(self) -> None:
        parsed = self.strict().parse("user@example.com")
        self.assertEqual((parsed.local_part, parsed.domain), ("user", "example.com"))

    def test_name_addr(self) -> None:
        parsed = self.strict().parse('"John Doe" <john@example.com>')
        self.assertEqual((parsed.display_name, parsed.local_part), ("John Doe", "john"))

    def test_angle_addr_without_display_name(self) -> None:
        self.assertEqual(self.strict().parse("<john@example.com>").local_part, "john")

    def test_address_group(self) -> None:
        parsed = self.strict().parse("A Group:user1@a.com, user2@b.com;")
        self.assertTrue(parsed.is_group)
        self.assertEqual([m.local_part for m in parsed.group_members], ["user1", "user2"])

    def test_empty_group(self) -> None:
        parsed = self.strict().parse("Undisclosed recipients:;")
        self.assertTrue(parsed.is_group)
        self.assertEqual(parsed.group_members, [])

    def test_parse_address_list_with_group_and_mailbox(self) -> None:
        parsed = self.strict().parse_address_list("Friends:a@b.com;, c@d.com")
        self.assertEqual([item.is_group for item in parsed], [True, False])

    def test_parse_mailbox_list(self) -> None:
        parsed = self.strict().parse_mailbox_list("a@b.com, c@d.com")
        self.assertEqual([item.domain for item in parsed], ["b.com", "d.com"])

    def test_mailbox_list_rejects_group(self) -> None:
        with self.assertRaises(RFC5322ParseError):
            self.strict().parse_mailbox_list("Friends:a@b.com;")

    def test_address_source_is_preserved(self) -> None:
        raw = "John <john@example.com>"
        self.assertEqual(self.strict().parse(raw).source, raw)

    def test_list_item_sources_and_comments_are_isolated(self) -> None:
        parsed = self.strict().parse_address_list("(a)a@b.com, (c)c@d.com")
        self.assertEqual([item.source for item in parsed], ["(a)a@b.com", "(c)c@d.com"])
        self.assertEqual([item.comments for item in parsed], [["a"], ["c"]])

    def test_comments_on_group_address(self) -> None:
        parsed = self.strict().parse("(team)Group:a@b.com;")
        self.assertEqual(parsed.comments, ["team"])

    def test_rejects_trailing_text(self) -> None:
        self.assert_rejects("user@example.com extra")

    def test_rejects_empty_list(self) -> None:
        with self.assertRaises(RFC5322ParseError):
            self.strict().parse_address_list("")


class TestAddrSpecAndDomainLiteral341(ParserAssertions, unittest.TestCase):
    def test_ipv4_domain_literal(self) -> None:
        self.assertEqual(self.strict().parse("user@[192.168.1.1]").domain, "[192.168.1.1]")

    def test_ipv6_domain_literal(self) -> None:
        parsed = self.strict().parse("postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]")
        self.assertEqual(parsed.domain, "[IPv6:2001:db8:85a3::8a2e:370:7334]")

    def test_general_domain_literal(self) -> None:
        self.assertEqual(self.strict().parse("user@[mail-router]").domain, "[mail-router]")

    def test_fws_inside_domain_literal(self) -> None:
        self.assertEqual(self.strict().parse("user@[mail\r\n \trouter]").domain, "[mail router]")

    def test_rejects_empty_domain_literal(self) -> None:
        self.assert_rejects("user@[]")

    def test_rejects_bad_ipv4_literal(self) -> None:
        self.assert_rejects("user@[999.168.1.1]")

    def test_rejects_bad_ipv6_literal(self) -> None:
        self.assert_rejects("user@[IPv6:not-an-ip]")

    def test_rejects_leading_dot_domain_in_strict_mode(self) -> None:
        self.assert_rejects("user@.example.com")


class TestObsoleteAddressing44(ParserAssertions, unittest.TestCase):
    def test_obs_local_part_mixes_atom_and_quoted_string(self) -> None:
        self.assertEqual(self.permissive().parse('user."quoted"@example.com').local_part, "user.quoted")

    def test_strict_rejects_obs_local_part(self) -> None:
        self.assert_rejects('user."quoted"@example.com')

    def test_obs_domain_leading_dot(self) -> None:
        self.assertEqual(self.permissive().parse("user@.leading-dot.com").domain, ".leading-dot.com")

    def test_strict_rejects_obs_domain_leading_dot(self) -> None:
        self.assert_rejects("user@.leading-dot.com")

    def test_obs_angle_route(self) -> None:
        parsed = self.permissive().parse("<@old.example,@relay.example:user@example.com>")
        self.assertEqual((parsed.local_part, parsed.domain), ("user", "example.com"))

    def test_strict_rejects_obs_angle_route(self) -> None:
        self.assert_rejects("<@old.example:user@example.com>")

    def test_obs_address_list_leading_empty_member(self) -> None:
        parsed = self.permissive().parse_address_list(", user@example.com")
        self.assertEqual(len(parsed), 1)

    def test_obs_address_list_trailing_empty_member(self) -> None:
        parsed = self.permissive().parse_address_list("user@example.com,")
        self.assertEqual(len(parsed), 1)

    def test_obs_group_list_commas(self) -> None:
        parsed = self.permissive().parse("Group:,, user@example.com,;")
        self.assertEqual(len(parsed.group_members), 1)


class TestEdgeCases(ParserAssertions, unittest.TestCase):
    def test_maximum_998_character_input_is_accepted(self) -> None:
        local = "a" * 992
        raw = f"{local}@x.com"
        self.assertEqual(len(raw), 998)
        self.assertEqual(self.strict().parse(raw).local_part, local)

    def test_999_character_input_is_rejected(self) -> None:
        self.assert_rejects(("a" * 993) + "@x.com")

    def test_deeply_nested_comments(self) -> None:
        parsed = self.strict().parse("(a(b(c)))user@example.com")
        self.assertEqual(parsed.comments, ["abc"])

    def test_comments_do_not_change_addr_spec_values(self) -> None:
        parsed = self.strict().parse("(a)user(b)@(c)example.com")
        self.assertEqual((parsed.local_part, parsed.domain), ("user", "example.com"))

    def test_group_member_comments_are_parsed(self) -> None:
        parsed = self.strict().parse("G:(a)user@example.com;")
        self.assertEqual(parsed.comments, ["a"])
        self.assertEqual(parsed.group_members[0].comments, ["a"])
        self.assertEqual(parsed.group_members[0].source, "(a)user@example.com")


class TestInvalidRejection(ParserAssertions, unittest.TestCase):
    def test_rejects_missing_at(self) -> None:
        self.assert_rejects("user.example.com")

    def test_rejects_missing_local_part(self) -> None:
        self.assert_rejects("@example.com")

    def test_rejects_missing_domain(self) -> None:
        self.assert_rejects("user@")

    def test_rejects_consecutive_dots_in_local_part(self) -> None:
        self.assert_rejects("user..name@example.com")

    def test_rejects_consecutive_dots_in_domain(self) -> None:
        self.assert_rejects("user@example..com")

    def test_rejects_unquoted_special_in_local_part(self) -> None:
        self.assert_rejects("user(name@example.com")

    def test_rejects_unclosed_domain_literal(self) -> None:
        self.assert_rejects("user@[example.com")

    def test_rejects_non_ascii(self) -> None:
        self.assert_rejects("usér@example.com")

    def test_rejects_trailing_comma_in_strict_address_list(self) -> None:
        with self.assertRaises(RFC5322ParseError):
            self.strict().parse_address_list("user@example.com,")


if __name__ == "__main__":
    unittest.main()
