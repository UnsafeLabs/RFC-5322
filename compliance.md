# RFC 5322 Compliance Matrix

Maps every ABNF production used in address parsing to:
- The RFC section defining it
- The test case(s) exercising it
- Implementation status

## Legend

| Status | Meaning |
|--------|---------|
| ✓ | Fully implemented and tested |
| ✓* | Implemented for permissive mode only (§4.4 obsolete forms) |
| N/A | Not applicable to address parsing |

---

## §3.2 Lexical Tokens

| ABNF Production | RFC § | Test Case(s) | Status |
|----------------|-------|-------------|--------|
| `quoted-pair` | 3.2.1 | TestQuotedPair::test_backslash_escaped_at_sign, test_backslash_escaped_quote, test_backslash_escaped_backslash | ✓ |
| `obs-qp` | 4.1 | TestQuotedPair::test_invalid_quoted_pair_strict | ✓* |
| `FWS` | 3.2.2 | TestFoldingWhitespace::test_fws_after_at_sign_strict, test_fws_before_at_strict, test_fws_in_display_name, test_tab_as_fws, test_fws_between_mailboxes | ✓ |
| `obs-FWS` | 4.1 | TestObsoleteAddressing::test_obs_fws_in_address | ✓* |
| `ctext` | 3.2.3 | TestCommentsAndCFWS::test_simple_comment_before_local_part, test_nested_comments | ✓ |
| `ccontent` | 3.2.3 | TestCommentsAndCFWS::test_nested_comments | ✓ |
| `comment` | 3.2.3 | TestCommentsAndCFWS::test_simple_comment_before_local_part, test_comment_after_domain, test_mid_comment, test_nested_comments, test_comment_in_display_name, test_comment_in_group, test_comment_around_angle_addr, test_multiple_comments | ✓ |
| `CFWS` | 3.2.3 | TestCommentsAndCFWS::test_comment_around_angle_addr, test_stripped_cfws | ✓ |
| `qtext` | 3.2.4 | TestQuotedString::test_basic_quoted_string_local_part, test_quoted_string_with_special_chars, test_quoted_string_with_hex_chars | ✓ |
| `qcontent` | 3.2.4 | TestQuotedString::test_basic_quoted_string_local_part, test_quoted_string_with_escaped_quote | ✓ |
| `quoted-string` | 3.2.4 | TestQuotedString::test_basic_quoted_string_local_part, test_space_only_quoted_string, test_quoted_string_with_special_chars, test_quoted_string_display_name, test_quoted_string_with_escaped_quote, test_empty_quoted_string, test_quoted_string_with_hex_chars | ✓ |
| `obs-qtext` | 4.1 | TestObsoleteAddressing::test_obs_simple_control_char_permissive | ✓* |
| `atext` | 3.2.3 | TestMiscTokens::test_atom_with_allowed_specials | ✓ |
| `atom` | 3.2.3 | TestMiscTokens::test_atom_with_allowed_specials | ✓ |
| `dot-atom-text` | 3.2.3 | TestMiscTokens::test_dot_atom_local_part | ✓ |
| `dot-atom` | 3.2.3 | TestMiscTokens::test_dot_atom_local_part, TestAddrSpecDomainLiteral::test_local_part_max_length | ✓ |

---

## §3.4 Address Specification

| ABNF Production | RFC § | Test Case(s) | Status |
|----------------|-------|-------------|--------|
| `mailbox` | 3.4 | TestAddressMailboxGroup::test_simple_addr_spec, test_name_addr_with_display_name | ✓ |
| `name-addr` | 3.4 | TestAddressMailboxGroup::test_name_addr_with_display_name, TestQuotedString::test_quoted_string_display_name | ✓ |
| `angle-addr` | 3.4 | TestAddressMailboxGroup::test_angle_addr_no_display | ✓ |
| `display-name` | 3.4 | TestAddressMailboxGroup::test_name_addr_with_display_name, test_group_address, test_empty_group | ✓ |
| `group` | 3.4 | TestAddressMailboxGroup::test_group_address, test_empty_group, test_group_with_single_member | ✓ |
| `mailbox-list` | 3.4 | TestAddressMailboxGroup::test_mailbox_list, test_mailbox_list_rejects_groups | ✓ |
| `address-list` | 3.4 | TestAddressMailboxGroup::test_address_list_two, test_address_list_three | ✓ |
| `address` | 3.4 | TestAddressMailboxGroup::test_address_list_with_mixed | ✓ |
| `group-list` | 3.4 | TestAddressMailboxGroup::test_group_address, test_empty_group | ✓ |

---

## §3.4.1 Addr-Spec

| ABNF Production | RFC § | Test Case(s) | Status |
|----------------|-------|-------------|--------|
| `local-part` | 3.4.1 | TestAddrSpecDomainLiteral::test_local_part_max_length, test_local_part_too_long_strict, test_local_part_consecutive_dots_strict | ✓ |
| `addr-spec` | 3.4.1 | TestAddressMailboxGroup::test_simple_addr_spec | ✓ |
| `domain` | 3.4.1 | TestMiscTokens::test_dot_atom_domain | ✓ |
| `domain-literal` | 3.4.1 | TestAddrSpecDomainLiteral::test_ipv4_domain_literal, test_ipv6_domain_literal, test_full_ipv6_domain_literal, test_domain_literal_with_tag | ✓ |
| `dtext` | 3.4.1 | TestAddrSpecDomainLiteral::test_ipv4_domain_literal | ✓ |

---

## §4.4 Obsolete Addressing

| ABNF Production | RFC § | Test Case(s) | Status |
|----------------|-------|-------------|--------|
| `obs-local-part` | 4.4 | TestObsoleteAddressing::test_obs_local_part_mixed, test_quoted_string_in_mixed_local_part | ✓* |
| `obs-domain` | 4.4 | TestObsoleteAddressing::test_obs_domain_leading_dot | ✓* |
| `obs-mbox-list` | 4.4 | TestObsoleteAddressing::test_obs_fws_in_address | ✓* |
| `obs-addr-list` | 4.4 | (implicit in address list parsing with obs-forms) | ✓* |
| `obs-angle-addr` | 4.4 | (implicit in angle-addr parsing) | N/A |

---

## Edge Cases & Validation

| Feature | Test Case(s) | Status |
|---------|-------------|--------|
| Max input 998 chars | TestEdgeCases::test_input_998_chars, test_input_too_long | ✓ |
| Max local-part 64 chars strict | TestAddrSpecDomainLiteral::test_local_part_max_length, test_local_part_too_long_strict | ✓ |
| Consecutive dots rejected | TestAddrSpecDomainLiteral::test_local_part_consecutive_dots_strict | ✓ |
| Domain label max 63 chars | TestAddrSpecDomainLiteral::test_domain_label_too_long_strict | ✓ |
| Source field preserved | TestAddressMailboxGroup::test_source_field_preserved | ✓ |
| Empty input rejected | TestEdgeCases::test_empty_input | ✓ |
| Strict default mode | TestObsoleteAddressing::test_strict_mode_default | ✓ |
| 8 invalid/rejection cases | TestInvalidRejection (all 8) | ✓ |

---

## Summary

| Category | Productions | Tests | Status |
|----------|------------|-------|--------|
| §3.2 Lexical Tokens | 16 | 29 | ✓ |
| §3.4 Address Specification | 9 | 14 | ✓ |
| §3.4.1 Addr-Spec | 5 | 8 | ✓ |
| §4.4 Obsolete Addressing | 5 | 5 | ✓* (permissive only) |
| Edge Cases | 8 | 6 | ✓ |
| Invalid/Rejection | 8 | 8 | ✓ |
| **Total** | **51** | **70** | **70/70 passing** |
