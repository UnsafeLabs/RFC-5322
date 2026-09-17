import unittest
from parser import AddressParser, RFC5322Address, ParseError

class TestRFC5322Parser(unittest.TestCase):
    def setUp(self):
        self.parser = AddressParser(strict=True)

    # §3.2.1 (quoted-pair): >=5 cases
    def test_quoted_pair_1(self):
        res = self.parser.parse('"quoted \\" string"@example.com')
        self.assertEqual(res[0].address, '"quoted " string"@example.com')
    def test_quoted_pair_2(self):
        res = self.parser.parse('"quoted \\\\ string"@example.com')
        self.assertEqual(res[0].address, '"quoted \\ string"@example.com')
    def test_quoted_pair_3(self):
        res = self.parser.parse('"\\a\\b\\c"@example.com')
        self.assertEqual(res[0].address, '"abc"@example.com')
    def test_quoted_pair_4(self):
        res = self.parser.parse('John \\"Doe\\" <john@example.com>')
        self.assertEqual(res[0].display_name, 'John " Doe"')
    def test_quoted_pair_5(self):
        res = self.parser.parse('John \\\\Doe <john@example.com>')
        self.assertEqual(res[0].display_name, 'John \\ Doe')

    # §3.2.2 (FWS): >=5 cases
    def test_fws_1(self):
        res = self.parser.parse('a@b.com \r\n \t , c@d.com')
        self.assertEqual(len(res), 2)
    def test_fws_2(self):
        res = self.parser.parse('John \r\n Doe <a@b.com>')
        self.assertEqual(res[0].display_name, 'John Doe')
    def test_fws_3(self):
        res = self.parser.parse('< \r\n a@b.com \r\n >')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_fws_4(self):
        res = self.parser.parse('Group \r\n Name : a@b.com ;')
        self.assertEqual(res[0].display_name, 'Group Name')
    def test_fws_5(self):
        res = self.parser.parse('a@ \r\n b.com')
        self.assertEqual(res[0].address, 'a@b.com')

    # §3.2.3 (CFWS/comments): >=8 cases
    def test_comment_1(self):
        res = self.parser.parse('a@b.com (comment)')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_2(self):
        res = self.parser.parse('(comment) a@b.com')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_3(self):
        res = self.parser.parse('a (c1) @ (c2) b.com')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_4(self):
        res = self.parser.parse('John (comment) Doe <a@b.com>')
        self.assertEqual(res[0].display_name, 'John Doe')
    def test_comment_5(self):
        res = self.parser.parse('a@b.com (nested (comment))')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_6(self):
        res = self.parser.parse('a@b.com (comment \\( with parens)')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_7(self):
        res = self.parser.parse('<a@b.com> (comment)')
        self.assertEqual(res[0].address, 'a@b.com')
    def test_comment_8(self):
        res = self.parser.parse('Group (comment): a@b.com;')
        self.assertEqual(res[0].display_name, 'Group')

    # §3.2.4 (quoted-string): >=8 cases
    def test_quoted_string_1(self):
        res = self.parser.parse('"John Doe" <a@b.com>')
        self.assertEqual(res[0].display_name, 'John Doe')
    def test_quoted_string_2(self):
        res = self.parser.parse('"J. Doe" <a@b.com>')
        self.assertEqual(res[0].display_name, 'J. Doe')
    def test_quoted_string_3(self):
        res = self.parser.parse('"" <a@b.com>')
        self.assertEqual(res[0].display_name, None)
    def test_quoted_string_4(self):
        res = self.parser.parse('"a b"@b.com')
        self.assertEqual(res[0].address, '"a b"@b.com')
    def test_quoted_string_5(self):
        res = self.parser.parse('"!@#"@b.com')
        self.assertEqual(res[0].address, '"!@#"@b.com')
    def test_quoted_string_6(self):
        res = self.parser.parse('" "@b.com')
        self.assertEqual(res[0].address, '" "@b.com')
    def test_quoted_string_7(self):
        res = self.parser.parse('"\\""@b.com')
        self.assertEqual(res[0].address, '"\""@b.com')
    def test_quoted_string_8(self):
        res = self.parser.parse('Group "Name": a@b.com;')
        self.assertEqual(res[0].display_name, 'Group Name')

    # §3.2.5 (misc): >=3 cases
    def test_misc_1(self):
        res = self.parser.parse('John Doe <a@b.com>')
        self.assertEqual(res[0].display_name, 'John Doe')
    def test_misc_2(self):
        res = self.parser.parse('!#$%&\'*+-/=?^_`{|}~@b.com')
        self.assertEqual(res[0].address, '!#$%&\'*+-/=?^_`{|}~@b.com')
    def test_misc_3(self):
        res = self.parser.parse('a@b-c.com')
        self.assertEqual(res[0].address, 'a@b-c.com')

    # §3.4, §3.4.1, and §4.4: >=28 cases combined
    def test_addr_1(self): self.assertEqual(self.parser.parse('a@b')[0].address, 'a@b')
    def test_addr_2(self): self.assertEqual(self.parser.parse('a.b@c.d')[0].address, 'a.b@c.d')
    def test_addr_3(self): self.assertEqual(self.parser.parse('<a@b>')[0].address, 'a@b')
    def test_addr_4(self): self.assertEqual(self.parser.parse('A <a@b>')[0].address, 'a@b')
    def test_addr_5(self): self.assertTrue(self.parser.parse('G:a@b;')[0].is_group)
    def test_addr_6(self): self.assertEqual(len(self.parser.parse('G:a@b,c@d;')[0].group_list), 2)
    def test_addr_7(self): self.assertEqual(self.parser.parse('a@[1.2.3.4]')[0].address, 'a@[1.2.3.4]')
    def test_addr_8(self): self.assertEqual(self.parser.parse('a@[IPv6:::1]')[0].address, 'a@[IPv6:::1]')
    def test_addr_9(self): self.assertEqual(len(self.parser.parse('a@b, c@d')), 2)
    def test_addr_10(self): self.assertEqual(len(self.parser.parse('a@b,c@d,e@f')), 3)
    def test_addr_11(self): self.assertEqual(self.parser.parse('G:;')[0].group_list, [])
    def test_addr_12(self): self.assertEqual(self.parser.parse('G: a@b ;')[0].display_name, 'G')
    def test_addr_13(self): self.assertEqual(self.parser.parse('A B C <a@b>')[0].display_name, 'A B C')
    def test_addr_14(self): self.assertEqual(self.parser.parse('"A B" C <a@b>')[0].display_name, 'A B C')
    def test_addr_15(self): self.assertEqual(self.parser.parse('a@b (C)')[0].address, 'a@b')
    def test_addr_16(self): self.assertEqual(self.parser.parse('a (B) @ c')[0].address, 'a@c')
    def test_addr_17(self): self.assertEqual(self.parser.parse('(A) b (C) @ (D) e (F)')[0].address, 'b@e')
    def test_addr_18(self): self.assertEqual(self.parser.parse('< (A) a@b (B) >')[0].address, 'a@b')
    def test_addr_19(self): self.assertEqual(self.parser.parse('G (A) : (B) a@b (C) ;')[0].display_name, 'G')
    def test_addr_20(self): self.assertEqual(self.parser.parse('G: a@b, c@d;')[0].group_list[1].address, 'c@d')
    def test_addr_21(self): self.assertEqual(self.parser.parse('G: A <a@b>;')[0].group_list[0].display_name, 'A')
    def test_addr_22(self): self.assertEqual(self.parser.parse('G1:a@b;, G2:c@d;')[1].display_name, 'G2')
    def test_addr_23(self): self.assertEqual(self.parser.parse('a@b, G:c@d;')[1].is_group, True)
    def test_addr_24(self): self.assertEqual(self.parser.parse('G:c@d;, a@b')[1].address, 'a@b')
    def test_addr_25(self): self.assertEqual(self.parser.parse('a@b , c@d')[1].address, 'c@d')
    def test_addr_26(self): self.assertEqual(self.parser.parse('a@b  ,c@d')[1].address, 'c@d')
    def test_addr_27(self): self.assertEqual(self.parser.parse('a@b ,  c@d')[1].address, 'c@d')
    def test_addr_28(self): self.assertEqual(self.parser.parse('a@b(C),c@d')[0].address, 'a@b')

    # Edge cases & Rejections: >=13 cases combined
    def test_edge_1(self):
        with self.assertRaises(ParseError): self.parser.parse('a@b (unclosed')
    def test_edge_2(self):
        with self.assertRaises(ParseError): self.parser.parse('"unclosed@b.com')
    def test_edge_3(self):
        with self.assertRaises(ParseError): self.parser.parse('a@b,,')
    def test_edge_4(self):
        with self.assertRaises(ParseError): self.parser.parse(',a@b')
    def test_edge_5(self):
        with self.assertRaises(ParseError): self.parser.parse('a@b,,c@d')
    def test_edge_6(self):
        with self.assertRaises(ParseError): self.parser.parse('G:a@b') # missing ;
    def test_edge_7(self):
        with self.assertRaises(ParseError): self.parser.parse('G:a@b,,;')
    def test_edge_8(self):
        with self.assertRaises(ParseError): self.parser.parse('G:;a@b')
    def test_edge_9(self):
        with self.assertRaises(ParseError): self.parser.parse('<a@b')
    def test_edge_10(self):
        with self.assertRaises(ParseError): self.parser.parse('a@b>')
    def test_edge_11(self):
        with self.assertRaises(ParseError): self.parser.parse('a b @ c')
    def test_edge_12(self):
        with self.assertRaises(ParseError): self.parser.parse('a @ b c')
    def test_edge_13(self):
        with self.assertRaises(ParseError): self.parser.parse('a@b c')

if __name__ == '__main__':
    unittest.main()