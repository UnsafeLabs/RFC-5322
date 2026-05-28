# RFC 5322 ABNF Grammar Compliance Matrix

This document maps all the standard and obsolete ABNF productions defined in RFC 5322 (and utilized for address parsing) to their implementation status and the corresponding test cases in `test_parser.py`.

| ABNF Production | RFC Section | Test Case(s) in `test_parser.py` | Status |
|-----------------|-------------|----------------------------------|--------|
| `address` | §3.4 | `test_mailbox_simple`, `test_group_empty`, `test_address_list_mixed` | Complete |
| `mailbox` | §3.4 | `test_mailbox_simple`, `test_name_addr_simple`, `test_name_addr_no_display` | Complete |
| `name-addr` | §3.4 | `test_name_addr_simple`, `test_name_addr_quoted`, `test_name_addr_no_display` | Complete |
| `angle-addr` | §3.4 | `test_name_addr_simple`, `test_name_addr_no_display`, `test_obs_angle_addr_route` | Complete |
| `addr-spec` | §3.4.1 | `test_mailbox_simple`, `test_dot_atom_local_part`, `test_domain_literal_ipv4` | Complete |
| `local-part` | §3.4.1 | `test_quoted_string_simple`, `test_dot_atom_local_part`, `test_obs_local_part_mixed` | Complete |
| `domain` | §3.4.1 | `test_dot_atom_domain`, `test_domain_literal_ipv4`, `test_obs_domain_cfws_around_dots` | Complete |
| `display-name` | §3.4 | `test_misc_display_name_mixed`, `test_misc_display_name_multiple_atoms`, `test_name_addr_quoted` | Complete |
| `phrase` | §3.2.5 | `test_misc_display_name_multiple_atoms`, `test_misc_display_name_mixed` | Complete |
| `word` | §3.2.5 | `test_misc_display_name_mixed`, `test_misc_display_name_multiple_atoms` | Complete |
| `atom` | §3.2.3 | `test_misc_atom_all_atext`, `test_misc_display_name_multiple_atoms` | Complete |
| `atext` | §3.2.3 | `test_misc_atom_all_atext` | Complete |
| `quoted-string` | §3.2.4 | `test_quoted_string_simple`, `test_quoted_string_with_space`, `test_quoted_string_escaped_quote` | Complete |
| `qcontent` | §3.2.4 | `test_quoted_string_escaped_quote`, `test_quoted_string_with_space` | Complete |
| `qtext` | §3.2.4 | `test_quoted_string_simple`, `test_quoted_string_with_space` | Complete |
| `quoted-pair` | §3.2.1 | `test_quoted_pair_escaped_char`, `test_quoted_pair_escaped_quote`, `test_quoted_pair_escaped_backslash` | Complete |
| `dot-atom` | §3.2.3 | `test_dot_atom_domain`, `test_dot_atom_local_part` | Complete |
| `dot-atom-text` | §3.2.3 | `test_dot_atom_domain`, `test_dot_atom_local_part` | Complete |
| `domain-literal` | §3.4.1 | `test_domain_literal_ipv4`, `test_domain_literal_ipv6`, `test_domain_literal_spaces` | Complete |
| `dtext` | §3.4.1 | `test_domain_literal_ipv4`, `test_domain_literal_ipv6` | Complete |
| `group` | §3.4 | `test_group_empty`, `test_group_one_member`, `test_group_multiple_members` | Complete |
| `group-list` | §3.4 | `test_group_one_member`, `test_group_multiple_members`, `test_obs_group_list_null_elements` | Complete |
| `mailbox-list` | §3.4 | `test_mailbox_list`, `test_group_multiple_members` | Complete |
| `address-list` | §3.4 | `test_address_list_mixed`, `test_obs_address_list_null_elements` | Complete |
| `CFWS` | §3.2.2 | `test_cfws_prepended`, `test_cfws_middle`, `test_cfws_domain_start`, `test_cfws_appended`, `test_cfws_multiple_comments` | Complete |
| `comment` | §3.2.2 | `test_cfws_nested_comments`, `test_cfws_escaped_parentheses`, `test_cfws_fws_inside`, `test_edge_deeply_nested_comments` | Complete |
| `ccontent` | §3.2.2 | `test_cfws_nested_comments`, `test_cfws_escaped_parentheses` | Complete |
| `ctext` | §3.2.2 | `test_cfws_prepended`, `test_cfws_nested_comments` | Complete |
| `FWS` | §3.2.2 | `test_fws_in_local_part`, `test_fws_in_quoted_string`, `test_fws_multiple_in_quoted`, `test_cfws_fws_inside` | Complete |
| `obs-local-part` | §4.4 | `test_obs_local_part_mixed`, `test_obs_local_part_multiple_quotes` | Complete |
| `obs-domain` | §4.4 | `test_obs_domain_cfws_around_dots` | Complete |
| `obs-route` | §4.4 | `test_obs_angle_addr_route`, `test_obs_angle_addr_multi_route` | Complete |
| `obs-group-list` | §4.4 | `test_obs_group_list_null_elements` | Complete |
| `obs-addr-list` | §4.4 | `test_obs_address_list_null_elements` | Complete |
| `obs-qtext` | §4.4 | `test_obs_qtext_ctrl_char` | Complete |
