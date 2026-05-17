"""Smoke and compliance tests for parser.py."""

from __future__ import annotations

import unittest

from parser import AddressParser, ParseError


STRICT_CASES = [
    ("s321_quoted_pair_quote", r'"quoted\"string"@example.com', {"local_part": 'quoted"string'}),
    ("s321_quoted_pair_backslash", r'"a\\b"@example.com', {"local_part": r"a\b"}),
    ("s321_quoted_pair_space", r'"a\ b"@example.com', {"local_part": "a b"}),
    ("s321_quoted_pair_tab", '"a\\\tb"@example.com', {"local_part": "a\tb"}),
    ("s321_quoted_pair_specials", r'"very.(),:;<>\"@[]\\ long"@example.com', {"local_part": 'very.(),:;<>"@[]\\ long'}),
    ("s322_fws_around_angle", '  John   <john@example.com>  ', {"display_name": "John", "local_part": "john"}),
    ("s322_fws_around_at", 'user \r\n\t @ \r\n example.com', {"local_part": "user", "domain": "example.com"}),
    ("s322_fws_in_quote", '"a\r\n b"@example.com', {"local_part": "a b"}),
    ("s322_tabs_between_tokens", '\tJane\t<jane@example.com>\t', {"display_name": "Jane"}),
    ("s322_fws_address_list", 'a@example.com,\r\n b@example.com', {"list_len": 2}),
    ("s323_comment_prefix", "(comment)user@example.com", {"comments": ["comment"], "local_part": "user"}),
    ("s323_comment_mid_addr", "user(mid)@(end)example.com", {"comments": ["mid", "end"]}),
    ("s323_nested_comment", "user(a(b)c)@example.com", {"comments": ["a(b)c"]}),
    ("s323_comment_suffix", "user@example.com (legacy display)", {"comments": ["legacy display"]}),
    ("s323_escaped_comment_paren", r"user(a\)b)@example.com", {"comments": ["a)b"]}),
    ("s323_comment_in_display", "John (Q) Doe <john@example.com>", {"display_name": "John Doe", "comments": ["Q"]}),
    ("s323_comment_before_domain_literal", "user@(net)[192.168.1.1]", {"comments": ["net"], "domain": "[192.168.1.1]"}),
    ("s323_group_comment", "Friends (team): a@example.com;", {"display_name": "Friends", "comments": ["team"]}),
    ("s324_quoted_local_space", '" "@example.com', {"local_part": " "}),
    ("s324_quoted_local_dot", '"john.doe"@example.com', {"local_part": "john.doe"}),
    ("s324_quoted_local_at", '"john@dept"@example.com', {"local_part": "john@dept"}),
    ("s324_quoted_display", '"John Doe" <john@example.com>', {"display_name": "John Doe"}),
    ("s324_quoted_display_comma", '"Doe, John" <john@example.com>', {"display_name": "Doe, John"}),
    ("s324_quoted_display_escaped", r'"Doe \"JD\"" <john@example.com>', {"display_name": 'Doe "JD"'}),
    ("s324_quoted_local_brackets", '"a[b]c"@example.com', {"local_part": "a[b]c"}),
    ("s324_empty_quoted_local", '""@example.com', {"local_part": ""}),
    ("s325_phrase_atoms", "John Q Public <john@example.com>", {"display_name": "John Q Public"}),
    ("s325_phrase_mixed", 'John "Q" Public <john@example.com>', {"display_name": "John Q Public"}),
    ("s325_unstructured_not_display", "alerts@example.com", {"display_name": None}),
    ("s34_simple_addr_spec", "user@example.com", {"local_part": "user", "domain": "example.com"}),
    ("s34_plus_tag", "user+tag@example.com", {"local_part": "user+tag"}),
    ("s34_name_addr", "John Doe <john@example.com>", {"display_name": "John Doe"}),
    ("s34_addr_list_two", "a@example.com, b@example.com", {"list_len": 2}),
    ("s34_addr_list_name_addr", "A <a@example.com>, B <b@example.com>", {"list_len": 2}),
    ("s34_mailbox_list", "a@example.com,b@example.com,c@example.com", {"mailbox_len": 3}),
    ("s34_group_two", "A Group:user1@a.com, user2@b.com;", {"is_group": True, "members": 2}),
    ("s34_empty_group", "Undisclosed:;", {"is_group": True, "members": 0}),
    ("s34_group_with_cfws", "Team: (none) ;", {"is_group": True, "members": 0, "comments": ["none"]}),
    ("s34_group_in_address_list", "Team:a@a.com;, b@b.com", {"list_len": 2}),
    ("s34_angle_with_domain_literal", "Postmaster <postmaster@[192.168.1.1]>", {"domain": "[192.168.1.1]"}),
    ("s34_comment_legacy_name", "john@example.com (John Doe)", {"comments": ["John Doe"]}),
    ("s341_ipv4_literal", "user@[192.168.1.1]", {"domain": "[192.168.1.1]"}),
    ("s341_ipv6_literal", "user@[IPv6:2001:db8::1]", {"domain": "[IPv6:2001:db8::1]"}),
    ("s341_full_ipv6_literal", "postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]", {"domain": "[IPv6:2001:db8:85a3::8a2e:370:7334]"}),
    ("s341_subdomains", "user@mail.example.co.uk", {"domain": "mail.example.co.uk"}),
    ("s341_dashed_domain", "user@mx-1.example.com", {"domain": "mx-1.example.com"}),
    ("s341_atext_domain", "user@x+y.example", {"domain": "x+y.example"}),
    ("s341_long_but_valid", f"{'a' * 64}@example.com", {"local_part": "a" * 64}),
    ("s341_literal_with_fws", "user@[192.168.1.1]", {"domain": "[192.168.1.1]"}),
    ("edge_max_length", f"{'a' * 60}@{'b' * 60}.com", {"domain": f"{'b' * 60}.com"}),
    ("edge_nested_comments_deep", "a(1(2(3)))@example.com", {"comments": ["1(2(3))"]}),
    ("edge_comment_only_group_list", "Empty:(comment);", {"is_group": True, "members": 0}),
    ("edge_multiple_comments", "(a)u(b)@(c)d.com(d)", {"comments": ["a", "b", "c", "d"]}),
    ("edge_empty_quoted_display", '"" <empty@example.com>', {"display_name": None}),
]


PERMISSIVE_CASES = [
    ("s44_obs_local_mixed", 'user."quoted"@example.com', {"local_part": 'user."quoted"'}),
    ("s44_obs_domain_leading_dot", "user@.leading-dot.com", {"domain": ".leading-dot.com"}),
    ("s44_obs_domain_trailing_dot", "user@example.com.", {"domain": "example.com."}),
    ("s44_obs_angle_route", "<@old.example,@relay.example:user@example.com>", {"local_part": "user"}),
    ("s44_obs_addr_list_leading_empty", ", a@example.com", {"list_len": 1}),
    ("s44_obs_addr_list_trailing_empty", "a@example.com,", {"list_len": 1}),
    ("s44_obs_addr_list_double_comma", "a@example.com,,b@example.com", {"list_len": 2}),
    ("s44_obs_group_empty_commas", "Old:,,;", {"is_group": True, "members": 0}),
    ("s44_obs_quoted_word_sequence", '"first"."last"@example.com', {"local_part": '"first"."last"'}),
]


INVALID_CASES = [
    ("invalid_missing_at", "user.example.com"),
    ("invalid_empty_local", "@example.com"),
    ("invalid_empty_domain", "user@"),
    ("invalid_double_dot_local", "user..name@example.com"),
    ("invalid_double_dot_domain", "user@example..com"),
    ("invalid_unclosed_quote", '"user@example.com'),
    ("invalid_unclosed_comment", "user(comment@example.com"),
    ("invalid_unclosed_literal", "user@[192.168.1.1"),
    ("invalid_bad_ipv4", "user@[999.999.999.999]"),
    ("invalid_bad_ipv6", "user@[IPv6:not-an-ip]"),
    ("invalid_obs_local_strict", 'user."quoted"@example.com'),
    ("invalid_obs_domain_strict", "user@.example.com"),
    ("invalid_empty_member_strict", "a@example.com,,b@example.com"),
]


class ParserGeneratedTests(unittest.TestCase):
    maxDiff = None

    def assert_address(self, raw: str, expected: dict[str, object], *, strict: bool = True) -> None:
        parser = AddressParser(strict=strict)
        if "list_len" in expected:
            self.assertEqual(len(parser.parse_address_list(raw)), expected["list_len"])
            return
        if "mailbox_len" in expected:
            self.assertEqual(len(parser.parse_mailbox_list(raw)), expected["mailbox_len"])
            return
        parsed = parser.parse(raw)
        for key, value in expected.items():
            if key == "members":
                self.assertEqual(len(parsed.group_members), value)
            else:
                self.assertEqual(getattr(parsed, key), value)
        self.assertEqual(parsed.source, raw)


def _add_success_case(name: str, raw: str, expected: dict[str, object], strict: bool) -> None:
    def test_case(self: ParserGeneratedTests) -> None:
        self.assert_address(raw, expected, strict=strict)

    setattr(ParserGeneratedTests, f"test_{name}", test_case)


def _add_invalid_case(name: str, raw: str) -> None:
    def test_case(self: ParserGeneratedTests) -> None:
        with self.assertRaises(ParseError):
            AddressParser(strict=True).parse(raw)

    setattr(ParserGeneratedTests, f"test_{name}", test_case)


for case_name, case_raw, case_expected in STRICT_CASES:
    _add_success_case(case_name, case_raw, case_expected, True)

for case_name, case_raw, case_expected in PERMISSIVE_CASES:
    _add_success_case(case_name, case_raw, case_expected, False)

for case_name, case_raw in INVALID_CASES:
    _add_invalid_case(case_name, case_raw)


if __name__ == "__main__":
    unittest.main()
