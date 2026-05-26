"""
Tests for RFC 5322 Email Address Parser.

Covers:
- §3.2: Lexical tokens (FWS, CFWS, comments)
- §3.3: Atoms, quoted-strings
- §3.4: Address specification (mailbox, addr-spec, group, name-addr)
- §4.4: Obsolete syntax
- Edge cases: quoted-pairs, domain-literals, nested comments
"""

import unittest
from parser import AddressParser, RFC5322Address, parse_email_address


class TestBasicAddrSpec(unittest.TestCase):
    """§3.4.1: Basic addr-spec parsing."""

    def test_simple(self):
        result = parse_email_address("user@example.com")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.addresses), 1)
        self.assertEqual(result.addresses[0].local_part, "user")
        self.assertEqual(result.addresses[0].domain, "example.com")
        self.assertIsNone(result.addresses[0].display_name)

    def test_domain_with_dots(self):
        result = parse_email_address("user@sub.example.co.uk")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].domain, "sub.example.co.uk")

    def test_local_part_with_dots(self):
        result = parse_email_address("firstname.lastname@example.com")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "firstname.lastname")

    def test_local_part_with_plus(self):
        result = parse_email_address("user+tag@example.com")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "user+tag")

    def test_unusual_atext(self):
        """Test all atext characters in local-part."""
        local = "!#$%&'*+-/=?^_`{|}~"
        result = parse_email_address(f"{local}@example.com")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, local)

    def test_numeric_domain(self):
        result = parse_email_address("user@123.456.789.0")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].domain, "123.456.789.0")

    def test_underscore_in_domain(self):
        result = parse_email_address("user@my_domain.com")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].domain, "my_domain.com")


class TestNameAddr(unittest.TestCase):
    """§3.4: display-name <addr-spec> format."""

    def test_display_name_basic(self):
        result = parse_email_address("John Doe <john@example.com>")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].display_name, "John Doe")
        self.assertEqual(result.addresses[0].local_part, "john")
        self.assertEqual(result.addresses[0].domain, "example.com")

    def test_display_name_quoted(self):
        result = parse_email_address('"John Q. Doe" <john@example.com>')
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].display_name, "John Q. Doe")

    def test_display_name_special_chars(self):
        result = parse_email_address("John (comment) <john@example.com>")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].display_name, "John")

    def test_no_display_name(self):
        result = parse_email_address("<user@example.com>")
        self.assertIsNone(result.error)
        self.assertIsNone(result.addresses[0].display_name)
        self.assertEqual(result.addresses[0].local_part, "user")

    def test_angle_addr_with_comments(self):
        result = parse_email_address("John (boss) <john@example.com>")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].display_name, "John")
        self.assertEqual(result.addresses[0].local_part, "john")
        self.assertEqual(result.addresses[0].domain, "example.com")


class TestQuotedString(unittest.TestCase):
    """§3.2.4: Quoted-string in local-part."""

    def test_quoted_local_part(self):
        result = parse_email_address('"john.doe"@example.com')
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, '"john.doe"')

    def test_quoted_local_part_with_spaces(self):
        result = parse_email_address('"john doe"@example.com')
        self.assertIsNone(result.error)

    def test_quoted_with_escaped_quotes(self):
        result = parse_email_address(r'"john\"doe"@example.com')
        self.assertIsNone(result.error)

    def test_quoted_with_escaped_backslash(self):
        result = parse_email_address(r'"john\\doe"@example.com')
        self.assertIsNone(result.error)


class TestDomainLiteral(unittest.TestCase):
    """§3.4.1: Domain literals like [192.168.1.1]."""

    def test_ipv4(self):
        result = parse_email_address("user@[192.168.1.1]")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].domain, "[192.168.1.1]")

    def test_ipv6(self):
        result = parse_email_address("user@[IPv6:2001:db8::1]")
        self.assertIsNone(result.error)
        self.assertIn("IPv6", result.addresses[0].domain)

    def test_domain_literal_text(self):
        result = parse_email_address("user@[TEXT]")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].domain, "[TEXT]")


class TestMultipleAddresses(unittest.TestCase):
    """§3.4: Address lists."""

    def test_two_simple(self):
        result = parse_email_address("alice@a.com, bob@b.com")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.addresses), 2)
        self.assertEqual(result.addresses[0].local_part, "alice")
        self.assertEqual(result.addresses[1].local_part, "bob")

    def test_three_addresses(self):
        result = parse_email_address("a@x.com, b@y.com, c@z.com")
        self.assertEqual(len(result.addresses), 3)

    def test_mixed_display_names(self):
        result = parse_email_address(
            "Alice <alice@a.com>, Bob <bob@b.com>"
        )
        self.assertIsNone(result.error)
        self.assertEqual(len(result.addresses), 2)
        self.assertEqual(result.addresses[0].display_name, "Alice")
        self.assertEqual(result.addresses[1].display_name, "Bob")


class TestGroups(unittest.TestCase):
    """§3.4: Group address syntax."""

    def test_group_basic(self):
        result = parse_email_address("Developers: alice@a.com, bob@b.com;")
        self.assertIsNone(result.error)
        self.assertEqual(len(result.addresses), 1)
        self.assertTrue(result.addresses[0].is_group)
        self.assertEqual(result.addresses[0].display_name, "Developers")
        self.assertEqual(len(result.addresses[0].group_members), 2)

    def test_group_empty(self):
        result = parse_email_address("Empty:;")
        self.assertIsNone(result.error)
        self.assertTrue(result.addresses[0].is_group)
        self.assertEqual(len(result.addresses[0].group_members), 0)

    def test_group_with_comment(self):
        result = parse_email_address("Team (members): a@b.com;")
        self.assertIsNone(result.error)
        self.assertTrue(result.addresses[0].is_group)


class TestComments(unittest.TestCase):
    """§3.2.2: Comments."""

    def test_comment_after_address(self):
        result = parse_email_address("user@example.com (comment)")
        self.assertIsNone(result.error)

    def test_comment_in_display_name(self):
        result = parse_email_address("John (CEO) <john@example.com>")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].display_name, "John")

    def test_nested_comments(self):
        result = parse_email_address("user@domain (outer (inner))")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "user")


class TestEdgeCases(unittest.TestCase):
    """Edge cases from RFC 5322 corner cases."""

    def test_case_insensitive_local(self):
        result = parse_email_address("USER@example.com")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "USER")

    def test_single_letter(self):
        result = parse_email_address("a@b.c")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "a")
        self.assertEqual(result.addresses[0].domain, "b.c")

    def test_long_domain(self):
        domain = "a." + "b." * 50 + "com"
        result = parse_email_address(f"user@{domain}")
        self.assertIsNone(result.error)

    def test_minimal_local(self):
        result = parse_email_address('""@example.com')
        # A quoted empty string is valid per RFC
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, '""')


class TestInvalidInputs(unittest.TestCase):
    """Invalid addresses that should fail or produce error."""

    def test_empty_input(self):
        result = parse_email_address("")
        self.assertIsNotNone(result.error)

    def test_no_at_sign(self):
        result = parse_email_address("notanemail")
        self.assertIsNotNone(result.error)

    def test_double_at(self):
        result = parse_email_address("user@@domain.com")
        self.assertIsNotNone(result.error)

    def test_starting_with_dot(self):
        result = parse_email_address(".user@domain.com")
        self.assertIsNotNone(result.error)

    def test_ending_with_dot(self):
        result = parse_email_address("user.@domain.com")
        self.assertIsNotNone(result.error)

    def test_consecutive_dots(self):
        result = parse_email_address("user..name@domain.com")
        self.assertIsNotNone(result.error)


class TestObsoleteSyntax(unittest.TestCase):
    """§4.4: Obsolete syntax handling."""

    def test_obs_domain(self):
        result = parse_email_address("user@[example]")
        self.assertIsNone(result.error)

    def test_obs_local(self):
        # Allow quoted-string in non-standard positions
        result = parse_email_address('"user"@domain.com')
        self.assertIsNone(result.error)


class TestRealWorld(unittest.TestCase):
    """Real-world email addresses."""

    def test_standard_email(self):
        result = parse_email_address("alice.smith@company.co.uk")
        self.assertIsNone(result.error)
        self.assertEqual(result.addresses[0].local_part, "alice.smith")
        self.assertEqual(result.addresses[0].domain, "company.co.uk")

    def test_display_with_multiword(self):
        result = parse_email_address(
            "Dr. Alice Smith <alice@hospital.org>"
        )
        self.assertIsNone(result.error)
        self.assertIn("Alice", result.addresses[0].display_name or "")

    def test_complex_display(self):
        result = parse_email_address(
            '"Smith, Alice" <alice@example.com>'
        )
        self.assertIsNone(result.error)
        self.assertEqual(len(result.addresses), 1)


class TestEdgeCaseSpecs(unittest.TestCase):
    """From the issue requirements."""

    def test_empty_domain_literal(self):
        result = parse_email_address("user@[]")
        self.assertEqual(result.addresses[0].domain, "[]")

    def test_comments_everywhere(self):
        result = parse_email_address(
            "Alice (my boss) <alice (work) @ (company) example.com>"
        )
        self.assertIsNone(result.error)

    def test_folding_whitespace(self):
        result = parse_email_address(
            "Really long name \r\n <user@example.com>"
        )
        self.assertIsNone(result.error)


if __name__ == "__main__":
    unittest.main()
