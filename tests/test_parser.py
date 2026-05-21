import unittest
from src.parser import RFC5322Parser

class TestRFC5322(unittest.TestCase):
    def test_simple_addr_spec(self):
        p = RFC5322Parser("john@example.com")
        res = p.parse_address_list()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["local"], "john")
        self.assertEqual(res[0]["domain"], "example.com")

    def test_name_addr(self):
        p = RFC5322Parser("John Doe <john.doe@example.com>")
        res = p.parse_address_list()
        self.assertEqual(res[0]["display_name"], "John Doe")
        self.assertEqual(res[0]["local"], "john.doe")

    def test_group(self):
        p = RFC5322Parser("Team: alice@work.com, bob@work.com ;")
        res = p.parse_address_list()
        self.assertEqual(res[0]["type"], "group")
        self.assertEqual(len(res[0]["members"]), 2)

    def test_comments_and_whitespace(self):
        p = RFC5322Parser(" (my comment) john (other) @ [127.0.0.1] ")
        res = p.parse_address_list()
        self.assertEqual(res[0]["local"], "john")
        self.assertEqual(res[0]["domain"], "[127.0.0.1]")

    def test_quoted_string(self):
        p = RFC5322Parser('"quoted local part"@example.com')
        res = p.parse_address_list()
        self.assertEqual(res[0]["local"], '"quoted local part"')

if __name__ == "__main__":
    unittest.main()
