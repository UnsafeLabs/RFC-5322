import unittest
from rfc_parser import parse_address, validate_address, EmailAddress, ParseError

class TestEmailParser(unittest.TestCase):
    def test_simple(self):
        e = parse_address("user@example.com")
        self.assertEqual(e.local_part, "user")
        self.assertEqual(e.domain, "example.com")
    
    def test_dot_atom(self):
        e = parse_address("first.last@example.co.uk")
        self.assertEqual(e.local_part, "first.last")
    
    def test_quoted_local(self):
        e = parse_address('"john.doe"@example.com')
        self.assertEqual(e.local_part, "john.doe")
    
    def test_quoted_escaped(self):
        e = parse_address(r'"john\"doe"@example.com')
        self.assertEqual(e.local_part, 'john"doe')
    
    def test_special_chars(self):
        e = parse_address("user+tag@example.com")
        self.assertEqual(e.local_part, "user+tag")
    
    def test_ip_domain(self):
        e = parse_address("user@[192.168.1.1]")
        self.assertEqual(e.domain, "[192.168.1.1]")
    
    def test_validate_true(self):
        self.assertTrue(validate_address("test@example.com"))
    
    def test_validate_false(self):
        self.assertFalse(validate_address("not-an-email"))
    
    def test_validate_no_at(self):
        self.assertFalse(validate_address("userexample.com"))
    
    def test_validate_empty(self):
        self.assertFalse(validate_address(""))

if __name__ == "__main__":
    unittest.main()
