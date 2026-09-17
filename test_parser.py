import unittest
from parser import AddressParser, RFC5322Address

class TestRFC5322Parser(unittest.TestCase):

    # =========================================================================
    # §3.2.1 (quoted-pair): at least 5 cases
    # =========================================================================
    def test_quoted_pair_simple(self):
        # Escaped char in quoted-string
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\\\\bar"@example.com')
        self.assertEqual(addr.local_part, 'foo\\bar')

    def test_quoted_pair_spaces(self):
        # Escaped space in quoted-string
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\\\\ bar"@example.com')
        self.assertEqual(addr.local_part, 'foo\\ bar')

    def test_quoted_pair_quote(self):
        # Escaped double quote in quoted-string
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\\\\\\"bar"@example.com')
        self.assertEqual(addr.local_part, 'foo\\"bar')

    def test_quoted_pair_slash(self):
        # Escaped backslash in quoted-string
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\\\\\\\\bar"@example.com')
        self.assertEqual(addr.local_part, 'foo\\\\bar')

    def test_quoted_pair_invalid_strict(self):
        # Strict mode rejects non-VCHAR/non-WSP escaped chars (like control chars)
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('"foo\\\x01bar"@example.com')

    # =========================================================================
    # §3.2.2 (FWS): at least 5 cases
    # =========================================================================
    def test_fws_simple_space(self):
        # FWS as space around '@'
        parser = AddressParser(strict=True)
        addr = parser.parse('user @ example.com')
        self.assertEqual(addr.local_part, 'user')
        self.assertEqual(addr.domain, 'example.com')

    def test_fws_crlf(self):
        # FWS folding with CRLF
        parser = AddressParser(strict=True)
        addr = parser.parse('user\r\n\t@example.com')
        self.assertEqual(addr.local_part, 'user')
        self.assertEqual(addr.domain, 'example.com')

    def test_fws_multiple(self):
        # Multiple spaces (runs of FWS)
        parser = AddressParser(strict=True)
        addr = parser.parse('user   @   example.com')
        self.assertEqual(addr.local_part, 'user')
        self.assertEqual(addr.domain, 'example.com')

    def test_fws_inside_quote(self):
        # FWS inside quoted-string
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\r\n bar"@example.com')
        self.assertEqual(addr.local_part, 'foo bar')

    def test_fws_inside_comment(self):
        # FWS inside comment
        parser = AddressParser(strict=True)
        addr = parser.parse('(foo\r\n bar)user@example.com')
        self.assertEqual(addr.comments, ['foo bar'])

    # =========================================================================
    # §3.2.3 (CFWS/comments): at least 8 cases
    # =========================================================================
    def test_cfws_comment_simple(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(comment)user@example.com')
        self.assertEqual(addr.comments, ['comment'])

    def test_cfws_comment_multiple(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(c1)user(c2)@(c3)example.com(c4)')
        self.assertEqual(addr.comments, ['c1', 'c2', 'c3', 'c4'])

    def test_cfws_comment_nested(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(outer (inner) comment)user@example.com')
        self.assertEqual(addr.comments, ['outer (inner) comment'])

    def test_cfws_comment_escaped_parens(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(comment with \\( parens)user@example.com')
        self.assertEqual(addr.comments, ['comment with ( parens'])

    def test_cfws_comment_fws(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(comment \r\n with fws)user@example.com')
        self.assertEqual(addr.comments, ['comment  with fws'])

    def test_cfws_comment_around_dot(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('user . (mid) name@example.com')
        self.assertEqual(addr.local_part, 'user.name')
        self.assertEqual(addr.comments, ['mid'])

    def test_cfws_comment_in_group(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('Group (c1) : user@example.com; (c2)')
        self.assertEqual(addr.comments, ['c1', 'c2'])

    def test_cfws_comment_in_angle_addr(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('<(c1)user@example.com(c2)>')
        self.assertEqual(addr.comments, ['c1', 'c2'])

    # =========================================================================
    # §3.2.4 (quoted-string): at least 8 cases
    # =========================================================================
    def test_qs_simple(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"simple"@example.com')
        self.assertEqual(addr.local_part, 'simple')

    def test_qs_all_specials(self):
        parser = AddressParser(strict=True)
        # quotes and backslashes escaped
        addr = parser.parse('"very.(),:;<>\\"@[]\\\\ long"@example.com')
        self.assertEqual(addr.local_part, 'very.(),:;<>"@[]\\ long')

    def test_qs_escaped(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\\"bar"@example.com')
        self.assertEqual(addr.local_part, 'foo"bar')

    def test_qs_empty(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('""@example.com')
        self.assertEqual(addr.local_part, '')

    def test_qs_with_fws(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"foo\r\n bar"@example.com')
        self.assertEqual(addr.local_part, 'foo bar')

    def test_qs_with_comments_outside(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(comment)"quoted"@example.com')
        self.assertEqual(addr.local_part, 'quoted')
        self.assertEqual(addr.comments, ['comment'])

    def test_qs_in_display_name(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"John Doe" <john@example.com>')
        self.assertEqual(addr.display_name, 'John Doe')

    def test_qs_special_chars(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('" \\"\\\\\\\t "@example.com')
        self.assertEqual(addr.local_part, ' "\\\t ')

    # =========================================================================
    # §3.2.5 (miscellaneous tokens): at least 3 cases
    # =========================================================================
    def test_misc_specials(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('user<name@domain.com')

    def test_misc_atext_all(self):
        parser = AddressParser(strict=True)
        raw = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~@example.com"
        addr = parser.parse(raw)
        self.assertEqual(addr.local_part, raw.split('@')[0])

    def test_misc_dot_atom_text(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('a.b.c.d@example.com')
        self.assertEqual(addr.local_part, 'a.b.c.d')

    # =========================================================================
    # §3.4 (address/mailbox/group): at least 12 cases
    # =========================================================================
    def test_addr_mailbox_simple(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('user@example.com')
        self.assertFalse(addr.is_group)
        self.assertEqual(addr.local_part, 'user')
        self.assertEqual(addr.domain, 'example.com')

    def test_addr_name_addr(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('John <john@example.com>')
        self.assertEqual(addr.display_name, 'John')
        self.assertEqual(addr.local_part, 'john')
        self.assertEqual(addr.domain, 'example.com')

    def test_addr_name_addr_quoted(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"John Doe" <john@example.com>')
        self.assertEqual(addr.display_name, 'John Doe')

    def test_addr_name_addr_no_display(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('<john@example.com>')
        self.assertIsNone(addr.display_name)
        self.assertEqual(addr.local_part, 'john')

    def test_addr_group_simple(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('MyGroup: john@example.com, jane@example.com;')
        self.assertTrue(addr.is_group)
        self.assertEqual(addr.display_name, 'MyGroup')
        self.assertEqual(len(addr.group_members), 2)
        self.assertEqual(addr.group_members[0].local_part, 'john')
        self.assertEqual(addr.group_members[1].local_part, 'jane')

    def test_addr_group_empty(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('EmptyGroup:;')
        self.assertTrue(addr.is_group)
        self.assertEqual(addr.display_name, 'EmptyGroup')
        self.assertEqual(len(addr.group_members), 0)

    def test_addr_group_nested_comments(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('Group (g) : john@example.com (m);')
        self.assertTrue(addr.is_group)
        self.assertEqual(addr.comments, ['g'])
        self.assertEqual(addr.group_members[0].comments, ['m'])

    def test_addr_mailbox_list(self):
        parser = AddressParser(strict=True)
        mboxes = parser.parse_mailbox_list('a@b.com, c@d.com')
        self.assertEqual(len(mboxes), 2)
        self.assertEqual(mboxes[0].local_part, 'a')
        self.assertEqual(mboxes[1].local_part, 'c')

    def test_addr_address_list(self):
        parser = AddressParser(strict=True)
        addrs = parser.parse_address_list('Group: a@b.com;, c@d.com')
        self.assertEqual(len(addrs), 2)
        self.assertTrue(addrs[0].is_group)
        self.assertFalse(addrs[1].is_group)

    def test_addr_list_cfws(self):
        parser = AddressParser(strict=True)
        mboxes = parser.parse_mailbox_list('a@b.com (comment1) , (comment2) c@d.com')
        self.assertEqual(len(mboxes), 2)
        self.assertEqual(mboxes[0].comments, ['comment1'])
        self.assertEqual(mboxes[1].comments, ['comment2'])

    def test_addr_group_semicolon_spaces(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('Group: a@b.com ;')
        self.assertTrue(addr.is_group)
        self.assertEqual(len(addr.group_members), 1)

    def test_addr_phrase_obs(self):
        # Display name with period is obsolete phrase (obs-phrase)
        parser = AddressParser(strict=False)
        addr = parser.parse('J. R. Ewing <jr@dallas.com>')
        self.assertEqual(addr.display_name, 'J. R. Ewing')

    # =========================================================================
    # §3.4.1 (addr-spec/domain-literal): at least 8 cases
    # =========================================================================
    def test_addr_spec_ipv4(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('user@[192.168.1.1]')
        self.assertEqual(addr.domain, '[192.168.1.1]')

    def test_addr_spec_ipv6(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('user@[IPv6:2001:db8::1]')
        self.assertEqual(addr.domain, '[IPv6:2001:db8::1]')

    def test_addr_spec_domain_literal_fws(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('user@[  192.168.1.1  ]')
        self.assertEqual(addr.domain, '[  192.168.1.1  ]')

    def test_addr_spec_quoted_local(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"user"@example.com')
        self.assertEqual(addr.local_part, 'user')

    def test_addr_spec_dot_atom(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('a.b.c@d.e.f')
        self.assertEqual(addr.local_part, 'a.b.c')
        self.assertEqual(addr.domain, 'd.e.f')

    def test_addr_spec_special_local(self):
        parser = AddressParser(strict=True)
        addr = parser.parse("!#$%&'*+-/=?^_`{|}~@example.com")
        self.assertEqual(addr.local_part, "!#$%&'*+-/=?^_`{|}~")

    def test_addr_spec_invalid_domain_literal_bracket(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('user@[192.168.1.1')

    def test_addr_spec_ipv6_complex(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]')
        self.assertEqual(addr.domain, '[IPv6:2001:db8:85a3::8a2e:370:7334]')

    # =========================================================================
    # §4.4 (obsolete addressing): at least 8 cases
    # =========================================================================
    def test_obs_local_part_mixed(self):
        # Mixed dot-atom and quoted-string
        parser = AddressParser(strict=False)
        addr = parser.parse('user."quoted"@example.com')
        self.assertEqual(addr.local_part, 'user.quoted')

    def test_obs_local_part_spaces(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('user . name @ example.com')
        self.assertEqual(addr.local_part, 'user.name')

    def test_obs_domain_spaces(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('user @ example . com')
        self.assertEqual(addr.domain, 'example.com')

    def test_obs_domain_leading_dot(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('user@.leading-dot.com')
        self.assertEqual(addr.domain, '.leading-dot.com')

    def test_obs_domain_consecutive_dots(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('user@domain..com')
        self.assertEqual(addr.domain, 'domain..com')

    def test_obs_angle_addr_route(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('<@route1.com,@route2.com:user@example.com>')
        self.assertEqual(addr.local_part, 'user')
        self.assertEqual(addr.domain, 'example.com')

    def test_obs_mbox_list_empty(self):
        parser = AddressParser(strict=False)
        mboxes = parser.parse_mailbox_list(', user1@a.com, , user2@b.com,')
        self.assertEqual(len(mboxes), 2)
        self.assertEqual(mboxes[0].local_part, 'user1')
        self.assertEqual(mboxes[1].local_part, 'user2')

    def test_obs_group_list_commas(self):
        parser = AddressParser(strict=False)
        addr = parser.parse('Group: , , ;')
        self.assertEqual(len(addr.group_members), 0)

    # =========================================================================
    # Edge cases (max lengths, empty parts, nested comments): at least 5 cases
    # =========================================================================
    def test_edge_max_length(self):
        parser = AddressParser(strict=True)
        # Construct input near 998 limit
        local_part = "a" * 400
        domain = "b" * 500
        raw = f"{local_part}@{domain}.com"
        self.assertTrue(len(raw) <= 998)
        addr = parser.parse(raw)
        self.assertEqual(addr.local_part, local_part)

    def test_edge_nested_comments_deep(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('((((deep))))user@example.com')
        self.assertEqual(addr.comments, ['(((deep)))'])

    def test_edge_empty_display_name_angle(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('"" <user@example.com>')
        self.assertEqual(addr.display_name, '')

    def test_edge_domain_literal_max(self):
        parser = AddressParser(strict=True)
        dtext = "x" * 900
        addr = parser.parse(f"user@[{dtext}]")
        self.assertEqual(addr.domain, f"[{dtext}]")

    def test_edge_consecutive_fws_comments(self):
        parser = AddressParser(strict=True)
        addr = parser.parse('(c1) \r\n (c2) user@example.com')
        self.assertEqual(addr.comments, ['c1', 'c2'])

    # =========================================================================
    # Invalid/rejection cases: at least 8 cases
    # =========================================================================
    def test_invalid_no_at(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('userexample.com')

    def test_invalid_double_at(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('user@@example.com')

    def test_invalid_leading_dot_strict(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('user@.leading-dot.com')

    def test_invalid_trailing_dot_strict(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('user@example.com.')

    def test_invalid_group_no_semicolon(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('Group: user@example.com')

    def test_invalid_unmatched_quote(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('"user@example.com')

    def test_invalid_unmatched_comment(self):
        parser = AddressParser(strict=True)
        with self.assertRaises(ValueError):
            parser.parse('(user@example.com')

    def test_invalid_line_length_strict(self):
        parser = AddressParser(strict=True)
        # Create input > 998 characters
        raw = "a" * 500 + "@" + "b" * 500 + ".com"
        self.assertTrue(len(raw) > 998)
        with self.assertRaises(ValueError):
            parser.parse(raw)


if __name__ == '__main__':
    unittest.main()
