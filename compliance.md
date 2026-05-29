# ABNF Compliance Matrix — RFC 5322 Parser

This matrix maps every ABNF production used in RFC 5322 address parsing to its defining RFC section, the corresponding test cases in `test_parser.py`, and its implementation status.

| ABNF Production | RFC Section | Test Case(s) | Status |
|:---|:---|:---|:---|
| `quoted-pair` | §3.2.1 | `test_quoted_pair_simple`, `test_quoted_pair_spaces`, `test_quoted_pair_quote`, `test_quoted_pair_slash`, `test_quoted_pair_invalid_strict` | Complete |
| `FWS` (Folding White Space) | §3.2.2 | `test_fws_simple_space`, `test_fws_crlf`, `test_fws_multiple`, `test_fws_inside_quote`, `test_fws_inside_comment` | Complete |
| `ctext` | §3.2.3 | `test_cfws_comment_simple`, `test_cfws_comment_multiple`, `test_cfws_comment_escaped_parens` | Complete |
| `ccontent` | §3.2.3 | `test_cfws_comment_simple`, `test_cfws_comment_multiple`, `test_cfws_comment_nested` | Complete |
| `comment` | §3.2.3 | `test_cfws_comment_simple`, `test_cfws_comment_multiple`, `test_cfws_comment_nested` | Complete |
| `CFWS` (Comment Folding White Space) | §3.2.3 | `test_cfws_comment_around_dot`, `test_cfws_comment_in_group`, `test_cfws_comment_in_angle_addr` | Complete |
| `atext` | §3.2.4 | `test_misc_specials`, `test_misc_atext_all` | Complete |
| `atom` | §3.2.4 | `test_misc_atext_all` | Complete |
| `dot-atom-text` | §3.2.4 | `test_misc_dot_atom_text` | Complete |
| `dot-atom` | §3.2.4 | `test_misc_dot_atom_text` | Complete |
| `qtext` | §3.2.4 | `test_qs_simple`, `test_qs_all_specials`, `test_qs_special_chars` | Complete |
| `qcontent` | §3.2.4 | `test_qs_simple`, `test_qs_all_specials`, `test_qs_escaped`, `test_qs_special_chars` | Complete |
| `quoted-string` | §3.2.4 | `test_qs_simple`, `test_qs_all_specials`, `test_qs_escaped`, `test_qs_empty`, `test_qs_with_fws`, `test_qs_with_comments_outside`, `test_qs_in_display_name`, `test_qs_special_chars` | Complete |
| `word` | §3.2.5 | `test_qs_in_display_name`, `test_addr_name_addr` | Complete |
| `phrase` | §3.2.5 | `test_addr_name_addr_quoted`, `test_addr_group_simple` | Complete |
| `display-name` | §3.4 | `test_qs_in_display_name`, `test_addr_name_addr_quoted` | Complete |
| `mailbox` | §3.4 | `test_addr_mailbox_simple`, `test_addr_name_addr`, `test_addr_name_addr_quoted`, `test_addr_name_addr_no_display` | Complete |
| `name-addr` | §3.4 | `test_addr_name_addr`, `test_addr_name_addr_quoted`, `test_addr_name_addr_no_display` | Complete |
| `angle-addr` | §3.4 | `test_addr_name_addr`, `test_addr_name_addr_quoted`, `test_addr_name_addr_no_display` | Complete |
| `group` | §3.4 | `test_addr_group_simple`, `test_addr_group_empty`, `test_addr_group_nested_comments` | Complete |
| `group-list` | §3.4 | `test_addr_group_simple`, `test_addr_group_empty`, `test_addr_group_nested_comments` | Complete |
| `address` | §3.4 | `test_addr_mailbox_simple`, `test_addr_group_simple` | Complete |
| `address-list` | §3.4 | `test_addr_address_list` | Complete |
| `mailbox-list` | §3.4 | `test_addr_mailbox_list`, `test_addr_list_cfws` | Complete |
| `local-part` | §3.4.1 | `test_addr_spec_quoted_local`, `test_addr_spec_dot_atom`, `test_addr_spec_special_local` | Complete |
| `domain` | §3.4.1 | `test_addr_spec_ipv4`, `test_addr_spec_ipv6`, `test_addr_spec_dot_atom` | Complete |
| `dtext` | §3.4.1 | `test_addr_spec_ipv4`, `test_addr_spec_ipv6`, `test_addr_spec_domain_literal_fws` | Complete |
| `domain-literal` | §3.4.1 | `test_addr_spec_ipv4`, `test_addr_spec_ipv6`, `test_addr_spec_domain_literal_fws`, `test_addr_spec_invalid_domain_literal_bracket`, `test_addr_spec_ipv6_complex` | Complete |
| `addr-spec` | §3.4.1 | `test_addr_mailbox_simple`, `test_addr_spec_ipv4`, `test_addr_spec_ipv6`, `test_addr_spec_domain_literal_fws`, `test_addr_spec_quoted_local`, `test_addr_spec_dot_atom`, `test_addr_spec_special_local`, `test_addr_spec_ipv6_complex` | Complete |
| `obs-qp` | §4.1 | `test_quoted_pair_invalid_strict` | Complete |
| `obs-ctext` | §4.1 | `test_cfws_comment_simple` | Complete |
| `obs-qtext` | §4.1 | `test_qs_special_chars` | Complete |
| `obs-qcontent` | §4.1 | `test_qs_special_chars` | Complete |
| `obs-dtext` | §4.1 | `test_addr_spec_domain_literal_fws` | Complete |
| `obs-phrase` | §4.4 | `test_addr_phrase_obs` | Complete |
| `obs-route` | §4.4 | `test_obs_angle_addr_route` | Complete |
| `obs-domain` | §4.4 | `test_obs_domain_spaces`, `test_obs_domain_leading_dot`, `test_obs_domain_consecutive_dots`, `test_invalid_leading_dot_strict`, `test_invalid_trailing_dot_strict` | Complete |
| `obs-local-part` | §4.4 | `test_obs_local_part_mixed`, `test_obs_local_part_spaces` | Complete |
| `obs-mailbox-list` | §4.4 | `test_obs_mbox_list_empty` | Complete |
| `obs-group-list` | §4.4 | `test_obs_group_list_commas` | Complete |
| `obs-addr-list` | §4.4 | `test_obs_mbox_list_empty` | Complete |
