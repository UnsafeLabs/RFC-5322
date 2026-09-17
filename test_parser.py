import pytest
from parser import AddressParser, RFC5322Address

# ==========================================
# §3.2.1 Quoted-Pair Tests (at least 5 cases)
# ==========================================

def test_quoted_pair_escaped_char():
    # Strict mode allows escaped VCHAR or WSP
    parser = AddressParser(strict=True)
    addr = parser.parse('"john\\\\doe"@example.com')
    assert addr.local_part == '"john\\\\doe"'
    
    addr = parser.parse('"john\\ doe"@example.com')
    assert addr.local_part == '"john\\ doe"'

def test_quoted_pair_escaped_quote():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john\\"doe"@example.com')
    assert addr.local_part == '"john\\"doe"'

def test_quoted_pair_escaped_backslash():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john\\\\\\\\doe"@example.com')
    assert addr.local_part == '"john\\\\\\\\doe"'

def test_quoted_pair_escaped_tab():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john\\\tdoe"@example.com')
    assert addr.local_part == '"john\\\tdoe"'

def test_quoted_pair_invalid_strict():
    parser = AddressParser(strict=True)
    # Strict mode rejects NUL character escaped
    with pytest.raises(ValueError):
        parser.parse('"john\\\x00doe"@example.com')

# ==========================================
# §3.2.2 FWS Tests (at least 5 cases)
# ==========================================

def test_fws_in_local_part():
    parser = AddressParser(strict=True)
    # FWS is standard WSP CRLF WSP
    addr = parser.parse('john \r\n @example.com')
    assert addr.local_part == 'john'
    assert addr.domain == 'example.com'

def test_fws_in_quoted_string():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john \r\n doe"@example.com')
    assert addr.local_part == '"john \r\n doe"'

def test_fws_multiple_in_quoted():
    parser = AddressParser(strict=True)
    addr = parser.parse('"a \r\n b \r\n c"@example.com')
    assert addr.local_part == '"a \r\n b \r\n c"'

def test_fws_invalid_crlf():
    parser = AddressParser(strict=True)
    # CRLF must be followed by at least one WSP
    with pytest.raises(ValueError):
        parser.parse('john\r\n@example.com')

def test_fws_permissive_lf_only():
    parser = AddressParser(strict=False)
    # Permissive mode allows just \n or \r
    addr = parser.parse('john\n @example.com')
    assert addr.local_part == 'john'

# ==========================================
# §3.2.3 CFWS/Comments Tests (at least 8 cases)
# ==========================================

def test_cfws_prepended():
    parser = AddressParser(strict=True)
    addr = parser.parse('(comment)user@example.com')
    assert addr.local_part == 'user'
    assert addr.comments == ['comment']

def test_cfws_middle():
    parser = AddressParser(strict=True)
    addr = parser.parse('user(middle)@example.com')
    assert addr.local_part == 'user'
    assert addr.comments == ['middle']

def test_cfws_domain_start():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@(end)example.com')
    assert addr.domain == 'example.com'
    assert addr.comments == ['end']

def test_cfws_appended():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@example.com(tail)')
    assert addr.domain == 'example.com'
    assert addr.comments == ['tail']

def test_cfws_multiple_comments():
    parser = AddressParser(strict=True)
    addr = parser.parse('(c1)user(c2)@(c3)example.com(c4)')
    assert addr.comments == ['c1', 'c2', 'c3', 'c4']

def test_cfws_nested_comments():
    parser = AddressParser(strict=True)
    addr = parser.parse('(outer (inner) comment)user@example.com')
    assert addr.comments == ['outer (inner) comment']

def test_cfws_escaped_parentheses():
    parser = AddressParser(strict=True)
    addr = parser.parse('(escaped \\( paren)user@example.com')
    assert addr.comments == ['escaped ( paren']
    
    addr = parser.parse('(escaped \\) paren)user@example.com')
    assert addr.comments == ['escaped ) paren']

def test_cfws_fws_inside():
    parser = AddressParser(strict=True)
    addr = parser.parse('(comment \r\n  with fws)user@example.com')
    assert addr.comments == ['comment \r\n  with fws']

# ==========================================
# §3.2.4 Quoted-String Tests (at least 8 cases)
# ==========================================

def test_quoted_string_simple():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john"@example.com')
    assert addr.local_part == '"john"'

def test_quoted_string_with_space():
    parser = AddressParser(strict=True)
    addr = parser.parse('"john doe"@example.com')
    assert addr.local_part == '"john doe"'

def test_quoted_string_escaped_quote():
    parser = AddressParser(strict=True)
    addr = parser.parse('"quoted\\"string"@example.com')
    assert addr.local_part == '"quoted\\"string"'

def test_quoted_string_escaped_backslash():
    parser = AddressParser(strict=True)
    addr = parser.parse('"quoted\\\\string"@example.com')
    assert addr.local_part == '"quoted\\\\string"'

def test_quoted_string_all_special_chars():
    parser = AddressParser(strict=True)
    addr = parser.parse('"very.(),:;<>\\"@[]\\\\ long"@example.com')
    assert addr.local_part == '"very.(),:;<>\\"@[]\\\\ long"'

def test_quoted_string_space_only():
    parser = AddressParser(strict=True)
    addr = parser.parse('" "@example.com')
    assert addr.local_part == '" "'

def test_quoted_string_empty():
    parser = AddressParser(strict=True)
    addr = parser.parse('""@example.com')
    assert addr.local_part == '""'

def test_quoted_string_nested_cfws():
    parser = AddressParser(strict=True)
    addr = parser.parse('(outer)"quoted"(inner)@example.com')
    assert addr.local_part == '"quoted"'
    assert addr.comments == ['outer', 'inner']

# ==========================================
# §3.2.5 Miscellaneous Tokens Tests (at least 3 cases)
# ==========================================

def test_misc_display_name_mixed():
    parser = AddressParser(strict=True)
    addr = parser.parse('John "Doe" <john@example.com>')
    assert addr.display_name == 'John Doe'
    assert addr.local_part == 'john'
    assert addr.domain == 'example.com'

def test_misc_display_name_multiple_atoms():
    parser = AddressParser(strict=True)
    addr = parser.parse('John Middle Doe <john@example.com>')
    assert addr.display_name == 'John Middle Doe'

def test_misc_atom_all_atext():
    parser = AddressParser(strict=True)
    addr = parser.parse("!#$%&'*+-/=?^_`{|}~@example.com")
    assert addr.local_part == "!#$%&'*+-/=?^_`{|}~"

# ==========================================
# §3.4 Address/Mailbox/Group Tests (at least 12 cases)
# ==========================================

def test_mailbox_simple():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@example.com')
    assert not addr.is_group
    assert addr.local_part == 'user'

def test_name_addr_simple():
    parser = AddressParser(strict=True)
    addr = parser.parse('John Doe <john@example.com>')
    assert addr.display_name == 'John Doe'
    assert addr.local_part == 'john'
    assert addr.domain == 'example.com'

def test_name_addr_quoted():
    parser = AddressParser(strict=True)
    addr = parser.parse('"John Doe" <john@example.com>')
    assert addr.display_name == 'John Doe'

def test_name_addr_no_display():
    parser = AddressParser(strict=True)
    addr = parser.parse('<john@example.com>')
    assert addr.display_name is None
    assert addr.local_part == 'john'

def test_group_empty():
    parser = AddressParser(strict=True)
    addr = parser.parse('A Group:;')
    assert addr.is_group
    assert addr.display_name == 'A Group'
    assert len(addr.group_members) == 0

def test_group_one_member():
    parser = AddressParser(strict=True)
    addr = parser.parse('A Group:user1@example.com;')
    assert addr.is_group
    assert len(addr.group_members) == 1
    assert addr.group_members[0].local_part == 'user1'

def test_group_multiple_members():
    parser = AddressParser(strict=True)
    addr = parser.parse('A Group:user1@example.com, user2@example.com;')
    assert addr.is_group
    assert len(addr.group_members) == 2
    assert addr.group_members[0].local_part == 'user1'
    assert addr.group_members[1].local_part == 'user2'

def test_group_quoted_display_name():
    parser = AddressParser(strict=True)
    addr = parser.parse('"Special Group":user1@example.com;')
    assert addr.is_group
    assert addr.display_name == 'Special Group'

def test_address_list_mixed():
    parser = AddressParser(strict=True)
    addr_list = parser.parse_address_list('user1@a.com, A Group:user2@b.com, user3@c.com;, user4@d.com')
    assert len(addr_list) == 3
    assert addr_list[0].local_part == 'user1'
    assert addr_list[1].is_group
    assert len(addr_list[1].group_members) == 2
    assert addr_list[2].local_part == 'user4'

def test_mailbox_list():
    parser = AddressParser(strict=True)
    mb_list = parser.parse_mailbox_list('user1@a.com, user2@b.com, "User 3" <user3@c.com>')
    assert len(mb_list) == 3
    assert mb_list[2].display_name == 'User 3'

def test_group_with_comments():
    parser = AddressParser(strict=True)
    addr = parser.parse('Group (desc): user1@example.com (c1);')
    assert addr.is_group
    # Group comments should include description and member's comments
    assert addr.comments == ['desc', 'c1']
    assert addr.group_members[0].comments == ['c1']

def test_mailbox_list_rejects_group():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse_mailbox_list('user1@a.com, Group:;')

# ==========================================
# §3.4.1 Addr-Spec/Domain-Literal (at least 8 cases)
# ==========================================

def test_domain_literal_ipv4():
    parser = AddressParser(strict=True)
    addr = parser.parse('user+tag@[192.168.1.1]')
    assert addr.domain == '[192.168.1.1]'

def test_domain_literal_ipv6():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@[IPv6:2001:db8::1]')
    assert addr.domain == '[IPv6:2001:db8::1]'

def test_domain_literal_spaces():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@[ 192.168.1.1 ]')
    assert addr.domain == '[ 192.168.1.1 ]'

def test_domain_literal_fws():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@[\r\n 192.168.1.1]')
    assert addr.domain == '[\r\n 192.168.1.1]'

def test_domain_literal_full_ipv6():
    parser = AddressParser(strict=True)
    addr = parser.parse('postmaster@[IPv6:2001:db8:85a3::8a2e:370:7334]')
    assert addr.domain == '[IPv6:2001:db8:85a3::8a2e:370:7334]'

def test_dot_atom_domain():
    parser = AddressParser(strict=True)
    addr = parser.parse('user@sub.domain.example.com')
    assert addr.domain == 'sub.domain.example.com'

def test_dot_atom_local_part():
    parser = AddressParser(strict=True)
    addr = parser.parse('first.last@example.com')
    assert addr.local_part == 'first.last'

def test_domain_literal_strict_rejects_quoted_pair():
    parser = AddressParser(strict=True)
    # Strict mode rejects backslash in domain literal
    with pytest.raises(ValueError):
        parser.parse('user@[192.168.\\1.1]')

# ==========================================
# §4.4 Obsolete Addressing (at least 8 cases)
# ==========================================

def test_obs_local_part_mixed():
    parser = AddressParser(strict=False)
    addr = parser.parse('user."quoted"@example.com')
    assert addr.local_part == 'user."quoted"'

def test_obs_domain_cfws_around_dots():
    parser = AddressParser(strict=False)
    addr = parser.parse('user@example (desc) . (desc) com')
    assert addr.domain == 'example.com'
    assert addr.comments == ['desc', 'desc']

def test_obs_local_part_multiple_quotes():
    parser = AddressParser(strict=False)
    addr = parser.parse('"first"."second"@example.com')
    assert addr.local_part == '"first"."second"'

def test_obs_angle_addr_route():
    parser = AddressParser(strict=False)
    addr = parser.parse('<@route.com:user@example.com>')
    assert addr.local_part == 'user'
    assert addr.domain == 'example.com'

def test_obs_angle_addr_multi_route():
    parser = AddressParser(strict=False)
    addr = parser.parse('<@a.com,@b.com:user@example.com>')
    assert addr.local_part == 'user'
    assert addr.domain == 'example.com'

def test_obs_address_list_null_elements():
    parser = AddressParser(strict=False)
    addr_list = parser.parse_address_list(', user1@example.com,, user2@example.com,')
    assert len(addr_list) == 2
    assert addr_list[0].local_part == 'user1'
    assert addr_list[1].local_part == 'user2'

def test_obs_group_list_null_elements():
    parser = AddressParser(strict=False)
    addr = parser.parse('Group:user1@example.com,,user2@example.com;')
    assert addr.is_group
    assert len(addr.group_members) == 2

def test_obs_qtext_ctrl_char():
    parser = AddressParser(strict=False)
    # Permissive allows ASCII 1 control character inside quoted-string
    addr = parser.parse('"ctrl\x01char"@example.com')
    assert addr.local_part == '"ctrl\x01char"'

# ==========================================
# Edge Cases (at least 5 cases)
# ==========================================

def test_edge_max_length_limit():
    parser = AddressParser(strict=True)
    # 998 characters is fine
    long_local = 'a' * 980
    addr = parser.parse(f'{long_local}@example.com')
    assert len(addr.local_part) == 980

def test_edge_exceed_length_limit():
    parser = AddressParser(strict=True)
    long_local = 'a' * 990
    with pytest.raises(ValueError):
        parser.parse(f'{long_local}@example.com') # exceeds 998 chars total

def test_edge_deeply_nested_comments():
    parser = AddressParser(strict=True)
    addr = parser.parse('(c1 (c2 (c3 (c4 (c5)))))user@example.com')
    assert addr.comments == ['c1 (c2 (c3 (c4 (c5))))']

def test_edge_empty_input():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('')

def test_edge_only_comments():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('(only comments)')

# ==========================================
# Invalid / Rejection Cases (at least 8 cases)
# ==========================================

def test_invalid_missing_at():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('userexample.com')

def test_invalid_trailing_dot():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('user.@example.com')

def test_invalid_leading_dot():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('.user@example.com')

def test_invalid_unclosed_comment():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('(comment user@example.com')

def test_invalid_unclosed_quotes():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('"user@example.com')

def test_invalid_unclosed_domain_literal():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('user@[192.168.1.1')

def test_invalid_consecutive_dots():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('user..name@example.com')

def test_invalid_special_chars_outside_quotes():
    parser = AddressParser(strict=True)
    with pytest.raises(ValueError):
        parser.parse('user[]@example.com')
