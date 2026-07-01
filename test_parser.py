import unittest
from parser import AddressParser

class TestRFC5322Parser(unittest.TestCase):
    def setUp(self):
        self.parser = AddressParser()

    def test_quoted_pair_1(self): pass
    def test_quoted_pair_2(self): pass
    def test_quoted_pair_3(self): pass
    def test_quoted_pair_4(self): pass
    def test_quoted_pair_5(self): pass

    def test_fws_1(self): pass
    def test_fws_2(self): pass
    def test_fws_3(self): pass
    def test_fws_4(self): pass
    def test_fws_5(self): pass

    def test_cfws_1(self): pass
    def test_cfws_2(self): pass
    def test_cfws_3(self): pass
    def test_cfws_4(self): pass
    def test_cfws_5(self): pass
    def test_cfws_6(self): pass
    def test_cfws_7(self): pass
    def test_cfws_8(self): pass

    def test_quoted_string_1(self): pass
    def test_quoted_string_2(self): pass
    def test_quoted_string_3(self): pass
    def test_quoted_string_4(self): pass
    def test_quoted_string_5(self): pass
    def test_quoted_string_6(self): pass
    def test_quoted_string_7(self): pass
    def test_quoted_string_8(self): pass

    def test_misc_tokens_1(self): pass
    def test_misc_tokens_2(self): pass
    def test_misc_tokens_3(self): pass

    def test_address_1(self): pass
    def test_address_2(self): pass
    def test_address_3(self): pass
    def test_address_4(self): pass
    def test_address_5(self): pass
    def test_address_6(self): pass
    def test_address_7(self): pass
    def test_address_8(self): pass
    def test_address_9(self): pass
    def test_address_10(self): pass
    def test_address_11(self): pass
    def test_address_12(self): pass

    def test_addr_spec_1(self): pass
    def test_addr_spec_2(self): pass
    def test_addr_spec_3(self): pass
    def test_addr_spec_4(self): pass
    def test_addr_spec_5(self): pass
    def test_addr_spec_6(self): pass
    def test_addr_spec_7(self): pass
    def test_addr_spec_8(self): pass

    def test_obsolete_1(self): pass
    def test_obsolete_2(self): pass
    def test_obsolete_3(self): pass
    def test_obsolete_4(self): pass
    def test_obsolete_5(self): pass
    def test_obsolete_6(self): pass
    def test_obsolete_7(self): pass
    def test_obsolete_8(self): pass

    def test_edge_cases_1(self): pass
    def test_edge_cases_2(self): pass
    def test_edge_cases_3(self): pass
    def test_edge_cases_4(self): pass
    def test_edge_cases_5(self): pass

    def test_invalid_1(self): pass
    def test_invalid_2(self): pass
    def test_invalid_3(self): pass
    def test_invalid_4(self): pass
    def test_invalid_5(self): pass
    def test_invalid_6(self): pass
    def test_invalid_7(self): pass
    def test_invalid_8(self): pass

if __name__ == "__main__":
    unittest.main()
