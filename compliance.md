# RFC 5322 Compliance Matrix

Maps ABNF productions to parser implementation and test coverage.

| ABNF Production | RFC § | Parser Method | Test Cases | Status |
|---|---|---|---|---|
| `address` | RFC 5322 §3.4 | `parse() / _parse_address()` | `test_mailbox_simple_addr_spec`, `test_mailbox_name_addr`, `test_group_empty`, `test_group_single_mailbox`, `test_*` | ✅ Complete |
| `mailbox` | RFC 5322 §3.4 | `_parse_mailbox()` | `test_mailbox_simple_addr_spec`, `test_mailbox_name_addr`, `test_mailbox_name_addr_no_space_before_angle`, `test_mailbox_angle_addr_only`, `test_mailbox_quoted_display_name` | ✅ Complete |
| `name-addr` | RFC 5322 §3.4 | `_parse_name_addr() / _parse_angle_addr()` | `test_mailbox_name_addr`, `test_mailbox_name_addr_no_space_before_angle`, `test_name_addr_cfws_around_angle` | ✅ Complete |
| `angle-addr` | RFC 5322 §3.4 | `_parse_angle_addr()` | `test_mailbox_angle_addr_only`, `test_name_addr_cfws_around_angle`, `test_unclosed_angle_bracket` | ✅ Complete |
| `addr-spec` | RFC 5322 §3.4.1 | `_parse_addr_spec()` | `test_addr_spec_minimal`, `test_addr_spec_common_form`, `test_addr_spec_missing_at_rejected`, `test_addr_spec_missing_domain_rejected`, `test_addr_spec_double_at_rejected`, `test_addr_spec_only_at_rejected` | ✅ Complete |
| `local-part` | RFC 5322 §3.4.1 | `_parse_local_part()` | `test_local_part_dot_atom`, `test_local_part_quoted_string`, `test_local_part_quoted_string_with_escape`, `test_local_part_case_preserved` | ✅ Complete |
| `domain` | RFC 5322 §3.4.1 | `_parse_domain()` | `test_domain_dot_atom`, `test_domain_subdomains`, `test_domain_literal_ipv4`, `test_domain_literal_ipv6`, `test_domain_literal_with_cfws`, `test_domain_literal_tag` | ✅ Complete |
| `domain-literal` | RFC 5322 §3.4.1 | `_parse_domain_literal()` | `test_domain_literal_ipv4`, `test_domain_literal_ipv6`, `test_domain_literal_with_cfws`, `test_domain_literal_tag` | ✅ Complete |
| `dot-atom` | RFC 5322 §3.2.3 | `_parse_dot_atom()` | `test_dot_atom_simple`, `test_dot_atom_multiple_dots`, `test_dot_atom_as_domain`, `test_dot_atom_trailing_dot_rejected`, `test_atom_leading_dot_fails`, `test_atom_consecutive_dots` | ✅ Complete |
| `quoted-string` | RFC 5322 §3.2.4 | `_parse_quoted_string()` | `test_quoted_string_simple`, `test_quoted_string_preserves_spaces`, `test_quoted_string_preserves_tabs`, `test_quoted_string_in_display_name`, `test_quoted_string_with_qtext_specials`, `test_quoted_string_empty`, `test_quoted_string_unclosed_rejected`, `test_quoted_string_with_crlf_strict` | ✅ Complete |
| `quoted-pair` | RFC 5322 §3.2.1 | `_parse_quoted_pair()` | `test_quoted_pair_in_quoted_string`, `test_quoted_pair_backslash_backslash`, `test_quoted_pair_in_display_name`, `test_quoted_pair_in_comment_strict`, `test_obs_qp_rejected_strict`, `test_obs_qp_accepted_permissive` | ✅ Complete |
| `CFWS` | RFC 5322 §3.2.2 | `_skip_cfws() / _parse_comment()` | `test_comment_before_address`, `test_comment_after_address_in_angle`, `test_comment_in_display_name`, `test_nested_comments`, `test_multiple_comments`, `test_comment_inside_angle_addr`, `test_fws_after_comma_in_list` | ✅ Complete |
| `FWS` | RFC 5322 §3.2.2 | `_skip_fws()` | `test_single_space_between_words`, `test_multiple_spaces_collapse`, `test_tab_between_words`, `test_fws_after_comma_in_list` | ✅ Complete |
| `comment` | RFC 5322 §3.2.2 | `_parse_comment()` | `test_comment_before_address`, `test_nested_comments`, `test_multiple_comments`, `test_comment_inside_angle_addr`, `test_comment_after_address_in_angle` | ✅ Complete |
| `phrase` | RFC 5322 §3.2.5 | `_parse_phrase()` | `test_phrase_single_word`, `test_phrase_multiple_words`, `test_phrase_mixed_atom_and_quoted`, `test_phrase_dots_between_atoms`, `test_phrase_dots_between_atoms_rejected_strict` | ✅ Complete |
| `atom` | RFC 5322 §3.2.3 | `_parse_atom()` | `test_atom_simple`, `test_atom_with_allowed_special_chars` | ✅ Complete |
| `word` | RFC 5322 §3.2.5 | `_parse_word()` | `test_phrase_single_word`, `test_phrase_multiple_words`, `test_phrase_mixed_atom_and_quoted` | ✅ Complete |
| `address-list` | RFC 5322 §3.4 | `parse_address_list()` | `test_address_list_two_simple`, `test_address_list_mixed_types`, `test_address_list_with_group`, `test_address_list_single_address`, `test_address_list_with_cfws` | ✅ Complete |
| `mailbox-list` | RFC 5322 §3.4 | `parse_mailbox_list()` | `test_mailbox_list_simple`, `test_mailbox_list_rejects_group_strict` | ✅ Complete |
| `group` | RFC 5322 §3.4 | `_parse_group()` | `test_group_empty`, `test_group_single_mailbox`, `test_group_multiple_mailboxes`, `test_group_multiple_mailboxes_with_names`, `test_group_cfws_after_colon`, `test_group_cfws_before_semicolon`, `test_group_not_closed_rejected`, `test_group_missing_colon_rejected` | ✅ Complete |
| `dtext` | RFC 5322 §3.4.1 | `_parse_domain_literal()` | `test_domain_literal_ipv4`, `test_domain_literal_tag` | ✅ Complete |
| `obs-local-part` | RFC 5322 §4.4 | `_parse_obs_local_part()` | `test_obs_local_part_with_dots`, `test_obs_local_part_atom_and_quoted` | ✅ Complete |
| `obs-domain` | RFC 5322 §4.4 | `_parse_obs_domain()` | `test_obs_domain_atoms` | ✅ Complete |
| `obs-angle-addr` | RFC 5322 §4.4 | `_parse_angle_addr() (permissive)` | `test_obs_angle_addr_single_hop`, `test_obs_angle_addr_multi_hop`, `test_obs_angle_addr_with_display_name`, `test_obs_angle_addr_rejected_strict` | ✅ Complete |
| `obs-route` | RFC 5322 §4.4 | `_parse_obs_route()` | `test_obs_angle_addr_single_hop`, `test_obs_angle_addr_multi_hop` | ✅ Complete |
| `obs-group-list` | RFC 5322 §4.4 | `_parse_group() (permissive)` | `test_obs_group_list_empty_with_commas` | ✅ Complete |
| `obs-mbox-list` | RFC 5322 §4.4 | `parse_mailbox_list() (permissive)` | `test_obs_mbox_list_trailing_comma`, `test_obs_mbox_list_leading_comma`, `test_obs_mbox_list_empty_elements` | ✅ Complete |
| `obs-addr-list` | RFC 5322 §4.4 | `parse_address_list() (permissive)` | `test_obs_addr_list_trailing_comma`, `test_obs_addr_list_leading_comma` | ✅ Complete |

## Summary

- **Parser**: `parser.py` — `RFC5322Address` dataclass + `AddressParser` class with `parse()`, `parse_address_list()`, `parse_mailbox_list()`
- **Tests**: `test_parser.py` — 112 test cases, all passing
- **Strict mode**: Rejects all `obs-*` productions from RFC 5322 §4.4
- **Permissive mode**: Accepts obsolete forms per §4.4
- **No external dependencies**: Pure Python stdlib only
- **Type hints**: All public methods annotated
- **Max line length**: 998 characters (RFC 5322 limit)
