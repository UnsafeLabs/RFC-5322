"""
Tests for RFC 5322 email address parser.
"""
import unittest
from parser import AddressParser, RFC5322Address, RFC5322SyntaxError


class TestAddressParser(unittest.TestCase):

    def setUp(self):
        self.parser = AddressParser(strict=True)
        self.relaxed = AddressParser(strict=False)

    # ── Simple addr-spec ─────────────────────────────────────────────

    def test_simple_addr_spec(self):
        addr = self.parser.parse("user@example.com")
        self.assertEqual(addr.local_part, "user")
        self.assertEqual(addr.domain, "example.com")
        self.assertIsNone(addr.display_name)

    def test_addr_spec_with_dots(self):
        addr = self.parser.parse("first.last@example.co.uk")
        self.assertEqual(addr.local_part, "first.last")
        self.assertEqual(addr.domain, "example.co.uk")

    def test_addr_spec_with_plus(self):
        addr = self.parser.parse("user+tag@example.com")
        self.assertEqual(addr.local_part, "user+tag")

    # ── Display name variants ────────────────────────────────────────

    def test_display_name_quoted(self):
        addr = self.parser.parse('"John Doe" <john@example.com>')
        self.assertEqual(addr.display_name, "John Doe")
        self.assertEqual(addr.local_part, "john")

    def test_display_name_unquoted(self):
        addr = self.parser.parse("John Doe <john@example.com>")
        self.assertEqual(addr.display_name, "John Doe")

    def test_display_name_with_dots(self):
        addr = self.relaxed.parse("John Q. Public <john@example.com>")
        self.assertEqual(addr.display_name, "John Q. Public")

    def test_display_name_special_chars(self):
        addr = self.parser.parse("John (home) <john@example.com>")
        self.assertEqual(addr.local_part, "john")

    # ── Quoted strings in local-part ─────────────────────────────────

    def test_quoted_local_part(self):
        addr = self.parser.parse('"john.doe"@example.com')
        self.assertEqual(addr.local_part, "john.doe")

    def test_quoted_local_part_with_spaces(self):
        addr = self.parser.parse('"john doe"@example.com')
        self.assertEqual(addr.local_part, "john doe")

    def test_quoted_local_part_with_quotes(self):
        addr = self.parser.parse(r'"john\"doe"@example.com')
        self.assertEqual(addr.local_part, 'john"doe')

    # ── Domain literal ───────────────────────────────────────────────

    def test_domain_literal_ipv4(self):
        addr = self.parser.parse("user@[192.168.1.1]")
        self.assertIn("192.168.1.1", addr.domain)

    def test_domain_literal_ipv6(self):
        addr = self.parser.parse("user@[IPv6:2001:db8::1]")
        self.assertIn("IPv6:2001:db8::1", addr.domain)

    def test_domain_literal_with_comments(self):
        addr = self.parser.parse("user@[10.0.0.1]")
        self.assertIn("10.0.0.1", addr.domain)

    # ── Address list ─────────────────────────────────────────────────

    def test_address_list_single(self):
        addrs = self.parser.parse_address_list("alice@example.com")
        self.assertEqual(len(addrs), 1)
        self.assertEqual(addrs[0].local_part, "alice")

    def test_address_list_multiple(self):
        addrs = self.parser.parse_address_list(
            "alice@a.com, bob@b.com, carol@c.com"
        )
        self.assertEqual(len(addrs), 3)
        self.assertEqual(addrs[0].local_part, "alice")
        self.assertEqual(addrs[1].local_part, "bob")
        self.assertEqual(addrs[2].local_part, "carol")

    def test_address_list_with_display_names(self):
        addrs = self.parser.parse_address_list(
            '"Alice" <alice@a.com>, Bob <bob@b.com>'
        )
        self.assertEqual(len(addrs), 2)
        self.assertEqual(addrs[0].display_name, "Alice")
        self.assertEqual(addrs[1].display_name, "Bob")

    # ── Group syntax ─────────────────────────────────────────────────

    def test_group_address(self):
        addr = self.parser.parse("Team: alice@a.com, bob@b.com;")
        self.assertTrue(addr.is_group)
        self.assertEqual(addr.display_name, "Team")
        self.assertEqual(len(addr.group_members), 2)
        self.assertEqual(addr.group_members[0].local_part, "alice")
        self.assertEqual(addr.group_members[1].local_part, "bob")

    def test_empty_group(self):
        addr = self.parser.parse("Team:;")
        self.assertTrue(addr.is_group)
        self.assertEqual(addr.display_name, "Team")
        self.assertEqual(len(addr.group_members), 0)

    # ── Comments ─────────────────────────────────────────────────────

    def test_comment_in_display_name(self):
        addr = self.parser.parse("John (comment) <john@example.com>")
        self.assertEqual(addr.display_name, "John")

    def test_nested_comments(self):
        addr = self.parser.parse("user@example.com")
        self.assertEqual(addr.local_part, "user")

    def test_comment_after_address(self):
        addr = self.parser.parse("user@example.com (contact)")
        self.assertEqual(addr.local_part, "user")
        self.assertIn("contact", " ".join(addr.comments))

    # ── Edge cases ──────────────────────────────────────────────────

    def test_percent_style(self):
        addr = self.relaxed.parse("user%example.com@other.com")
        self.assertEqual(addr.local_part, "user%example.com")

    def test_dot_atom_with_multiple_dots(self):
        addr = self.parser.parse("a.b.c.d@example.com")
        self.assertEqual(addr.local_part, "a.b.c.d")

    def test_numbers_in_local_part(self):
        addr = self.parser.parse("user123@example.com")
        self.assertEqual(addr.local_part, "user123")

    def test_special_chars_in_local_part(self):
        addr = self.parser.parse("nice&simple@example.com")
        self.assertEqual(addr.local_part, "nice&simple")

    def test_underscore_in_domain(self):
        addr = self.parser.parse("user@my_host.com")
        self.assertEqual(addr.domain, "my_host.com")

    # ── RFC 5322 specific test cases ─────────────────────────────────

    def test_rfc5322_sample_simple(self):
        """Simple addr-spec form."""
        addr = self.parser.parse("john.doe@example.com")
        self.assertEqual(addr.local_part, "john.doe")
        self.assertEqual(addr.domain, "example.com")

    def test_rfc5322_sample_quoted_display(self):
        """Display name with quoted string."""
        addr = self.parser.parse('"John Doe" <john.doe@example.com>')
        self.assertEqual(addr.display_name, "John Doe")
        self.assertEqual(addr.local_part, "john.doe")

    def test_rfc5322_sample_bare_addr_spec(self):
        """Just addr-spec, no display name."""
        addr = self.parser.parse("john.doe@example.com")
        self.assertIsNone(addr.display_name)

    def test_rfc5322_multiple_mailboxes(self):
        """Comma-separated addresses."""
        addrs = self.parser.parse_address_list(
            "alice@example.com, bob@example.com"
        )
        self.assertEqual(len(addrs), 2)

    # ── Error handling ───────────────────────────────────────────────

    def test_invalid_missing_at(self):
        with self.assertRaises(RFC5322SyntaxError):
            self.parser.parse("notanemail")

    def test_invalid_empty_string(self):
        addrs = self.parser.parse_address_list("")
        self.assertEqual(len(addrs), 0)

    def test_invalid_unterminated_quoted(self):
        with self.assertRaises(RFC5322SyntaxError):
            self.parser.parse('"unclosed <test@test.com>')

    def test_unterminated_angle(self):
        with self.assertRaises(RFC5322SyntaxError):
            self.parser.parse("<user@example.com")

    # ── Real-world email addresses ──────────────────────────────────

    def test_real_world_gmail(self):
        addr = self.parser.parse("user@gmail.com")
        self.assertEqual(addr.local_part, "user")
        self.assertEqual(addr.domain, "gmail.com")

    def test_real_world_subdomain(self):
        addr = self.parser.parse("user@sub.example.com")
        self.assertEqual(addr.domain, "sub.example.com")

    def test_real_world_long_domain(self):
        addr = self.parser.parse("user@really.long.domain.name.com")
        self.assertEqual(addr.domain, "really.long.domain.name.com")

    def test_real_world_with_name(self):
        addr = self.parser.parse("Alice <alice@example.com>")
        self.assertEqual(addr.display_name, "Alice")
        self.assertEqual(addr.local_part, "alice")

    def test_real_world_multi_word_name(self):
        addr = self.parser.parse("Alice Bob <alice@example.com>")
        self.assertEqual(addr.display_name, "Alice Bob")


if __name__ == "__main__":
    unittest.main()
