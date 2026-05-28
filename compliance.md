# RFC 5322 Compliance Matrix

This document maps every ABNF production used in address parsing to:
- The RFC section defining it
- The test case(s) exercising it
- Implementation status

## §3.2.1 — Quoted-Pair

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `quoted-pair` | §3.2.1 | `test_quoted_backslash_in_quoted_string`, `test_quoted_quote_in_quoted_string`, `test_quoted_special_chars`, `test_quoted_at_sign`, `test_quoted_parentheses` | ✅ Complete |
| `obs-qp` | §4.1 | `test_obs_qp` (permissive mode) | ✅ Complete |

## §3.2.2 — Folding White Space and Comments

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `FWS` | §3.2.2 | `test_fws_in_display_name`, `test_fws_before_at`, `test_fws_after_at`, `test_fws_in_domain_literal`, `test_fws_in_quoted_string` | ✅ Complete |
| `ctext` | §3.2.2 | Used in `test_comment_with_special_chars` | ✅ Complete |
| `ccontent` | §3.2.2 | Used in `test_nested_comments` | ✅ Complete |
| `comment` | §3.2.2 | `test_comment_before_addr_spec`, `test_comment_after_addr_spec`, `test_comment_in_display_name`, `test_nested_comments`, `test_comment_with_special_chars`, `test_multiple_comments`, `test_comment_with_fws`, `test_comment_in_angle_addr` | ✅ Complete |
| `CFWS` | §3.2.2 | `test_comment_before_addr_spec`, `test_comment_after_addr_spec`, `test_comment_in_display_name`, `test_nested_comments`, `test_comment_with_special_chars`, `test_multiple_comments`, `test_comment_with_fws`, `test_comment_in_angle_addr` | ✅ Complete |
| `obs-FWS` | §4.2 | `test_obs_fws` (permissive mode) | ✅ Complete |

## §3.2.3 — Atom

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `atext` | §3.2.3 | Used in `test_atom_as_local_part`, `test_dot_atom_as_local_part`, `test_atom_with_special_chars` | ✅ Complete |
| `atom` | §3.2.3 | `test_atom_as_local_part`, `test_atom_with_special_chars` | ✅ Complete |
| `dot-atom-text` | §3.2.3 | `test_dot_atom_as_local_part` | ✅ Complete |
| `dot-atom` | §3.2.3 | `test_dot_atom_as_local_part`, `test_simple_addr_spec` | ✅ Complete |
| `specials` | §3.2.3 | N/A (reference only) | N/A |

## §3.2.4 — Quoted Strings

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `qtext` | §3.2.4 | `test_simple_quoted_string`, `test_quoted_string_with_spaces` | ✅ Complete |
| `qcontent` | §3.2.4 | `test_quoted_string_with_special_chars` | ✅ Complete |
| `quoted-string` | §3.2.4 | `test_simple_quoted_string`, `test_quoted_string_with_spaces`, `test_quoted_string_with_special_chars`, `test_quoted_string_with_folding`, `test_quoted_string_display_name`, `test_quoted_string_empty`, `test_quoted_string_with_at`, `test_quoted_string_with_backslash` | ✅ Complete |

## §3.2.5 — Miscellaneous Tokens

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `word` | §3.2.5 | `test_atom_as_local_part`, `test_dot_atom_as_local_part` | ✅ Complete |
| `phrase` | §3.2.5 | `test_name_addr`, `test_name_addr_quoted` | ✅ Complete |
| `obs-phrase` | §4.2 | Used in permissive mode | ✅ Complete |

## §3.4 — Address Specification

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `address` | §3.4 | `test_simple_addr_spec`, `test_name_addr`, `test_name_addr_quoted`, `test_group_simple`, `test_group_empty`, `test_group_single_member`, `test_group_with_name_addr`, `test_address_list`, `test_mailbox_list`, `test_mixed_address_list`, `test_addr_spec_with_comments`, `test_name_addr_no_display` | ✅ Complete |
| `mailbox` | §3.4 | `test_simple_addr_spec`, `test_name_addr`, `test_name_addr_quoted` | ✅ Complete |
| `name-addr` | §3.4 | `test_name_addr`, `test_name_addr_quoted` | ✅ Complete |
| `angle-addr` | §3.4 | `test_name_addr`, `test_name_addr_quoted`, `test_name_addr_no_display` | ✅ Complete |
| `group` | §3.4 | `test_group_simple`, `test_group_empty`, `test_group_single_member`, `test_group_with_name_addr` | ✅ Complete |
| `display-name` | §3.4 | `test_name_addr`, `test_name_addr_quoted` | ✅ Complete |
| `mailbox-list` | §3.4 | `test_mailbox_list` | ✅ Complete |
| `address-list` | §3.4 | `test_address_list`, `test_mixed_address_list` | ✅ Complete |
| `group-list` | §3.4 | `test_group_simple`, `test_group_empty`, `test_group_single_member`, `test_group_with_name_addr` | ✅ Complete |

## §3.4.1 — Addr-Spec Specification

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `addr-spec` | §3.4.1 | `test_simple_addr_spec`, `test_addr_spec_with_tag`, `test_addr_spec_with_dots`, `test_quoted_local_part` | ✅ Complete |
| `local-part` | §3.4.1 | `test_simple_addr_spec`, `test_addr_spec_with_tag`, `test_addr_spec_with_dots`, `test_quoted_local_part` | ✅ Complete |
| `domain` | §3.4.1 | `test_simple_addr_spec`, `test_addr_spec_with_tag`, `test_addr_spec_with_dots` | ✅ Complete |
| `domain-literal` | §3.4.1 | `test_domain_literal_ipv4`, `test_domain_literal_ipv6`, `test_domain_literal_with_spaces`, `test_domain_literal_full_ipv6` | ✅ Complete |
| `dtext` | §3.4.1 | `test_domain_literal_ipv4`, `test_domain_literal_ipv6` | ✅ Complete |

## §4.4 — Obsolete Addressing

| ABNF Production | RFC Section | Test Cases | Status |
|----------------|-------------|------------|--------|
| `obs-angle-addr` | §4.4 | `test_obs_angle_addr` (permissive mode) | ✅ Complete |
| `obs-route` | §4.4 | `test_obs_angle_addr` (permissive mode) | ✅ Complete |
| `obs-domain-list` | §4.4 | `test_obs_angle_addr` (permissive mode) | ✅ Complete |
| `obs-local-part` | §4.4 | `test_obs_local_part_mixed` (permissive mode) | ✅ Complete |
| `obs-domain` | §4.4 | `test_obs_domain`, `test_obs_domain_atom` (permissive mode) | ✅ Complete |
| `obs-dtext` | §4.4 | `test_obs_dtext` (permissive mode) | ✅ Complete |
| `obs-mbox-list` | §4.4 | N/A | N/A |
| `obs-addr-list` | §4.4 | N/A | N/A |
| `obs-group-list` | §4.4 | N/A | N/A |

## Test Coverage Summary

| Category | Required | Implemented | Status |
|----------|----------|-------------|--------|
| §3.2.1 (quoted-pair) | 5 | 5 | ✅ |
| §3.2.2 (FWS) | 5 | 5 | ✅ |
| §3.2.3 (CFWS/comments) | 8 | 8 | ✅ |
| §3.2.4 (quoted-string) | 8 | 8 | ✅ |
| §3.2.5 (miscellaneous tokens) | 3 | 3 | ✅ |
| §3.4 (address/mailbox/group) | 12 | 12 | ✅ |
| §3.4.1 (addr-spec/domain-literal) | 8 | 8 | ✅ |
| §4.4 (obsolete addressing) | 8 | 8 | ✅ |
| Edge cases | 5 | 5 | ✅ |
| Invalid/rejection cases | 8 | 8 | ✅ |
| **Total** | **70** | **70** | **✅** |
