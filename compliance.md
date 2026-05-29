# RFC 5322 Address Parser Compliance Matrix

This matrix maps the address parsing ABNF used by RFC 5322 sections 3.2 through 3.4 and obsolete address forms from section 4.4 to the parser implementation and tests.

| ABNF production | RFC section | Implementation | Test coverage |
| --- | --- | --- | --- |
| quoted-pair | 3.2.1 | Complete, handled in quoted strings, comments, and permissive domain literals | test_s321_quoted_pair_quote, test_s321_quoted_pair_backslash, test_s321_quoted_pair_space, test_s321_quoted_pair_tab, test_s321_quoted_pair_specials |
| FWS | 3.2.2 | Complete for CRLF folding and token-adjacent whitespace normalization | test_s322_fws_around_angle, test_s322_fws_around_at, test_s322_fws_in_quote, test_s322_tabs_between_tokens, test_s322_fws_address_list |
| ctext | 3.2.2 | Complete for printable comment content excluding unescaped parens and backslash | test_s323_comment_prefix, test_s323_comment_mid_addr, test_s323_nested_comment |
| ccontent | 3.2.2 | Complete for ctext, quoted-pair, and nested comment recursion | test_s323_nested_comment, test_s323_escaped_comment_paren |
| comment | 3.2.2 | Complete, including nesting and escaped parens | test_s323_nested_comment, test_s323_escaped_comment_paren, test_invalid_unclosed_comment |
| CFWS | 3.2.2 | Complete around address tokens, stripped semantically while preserving comments | test_s323_comment_before_domain_literal, test_s323_comment_suffix, test_s323_group_comment |
| atext | 3.2.3 | Complete for atom and dot-atom validation | test_s34_plus_tag, test_s341_atext_domain |
| atom | 3.2.3 | Complete with CFWS stripped by lexer | test_s325_phrase_atoms, test_s44_obs_domain_leading_dot |
| dot-atom-text | 3.2.3 | Complete with empty segment rejection in strict mode | test_s34_simple_addr_spec, test_invalid_double_dot_local, test_invalid_double_dot_domain |
| dot-atom | 3.2.3 | Complete for strict local-part and domain | test_s341_subdomains, test_s341_dashed_domain |
| specials | 3.2.3 | Complete by exclusion from ATEXT | test_s324_quoted_local_at, test_s321_quoted_pair_specials |
| qtext | 3.2.4 | Complete for printable quoted content excluding quote and backslash | test_s324_quoted_local_dot, test_s324_quoted_local_brackets |
| qcontent | 3.2.4 | Complete for qtext and quoted-pair | test_s324_quoted_display_escaped, test_s321_quoted_pair_quote |
| quoted-string | 3.2.4 | Complete with escaped chars and folded whitespace handling | test_s324_quoted_local_space, test_s324_empty_quoted_local, test_s324_quoted_display |
| word | 3.2.5 | Complete for phrase parsing and obs-local-part | test_s325_phrase_mixed, test_s44_obs_quoted_word_sequence |
| phrase | 3.2.5 | Complete for display-name | test_s325_phrase_atoms, test_s324_quoted_display_comma |
| address | 3.4 | Complete for mailbox and group | test_s34_group_two, test_s34_group_in_address_list |
| mailbox | 3.4 | Complete for name-addr and addr-spec | test_s34_name_addr, test_s34_simple_addr_spec |
| name-addr | 3.4 | Complete with optional display-name and angle-addr | test_s34_name_addr, test_s324_quoted_display |
| angle-addr | 3.4 | Complete in strict mode for normal angle addresses | test_s34_angle_with_domain_literal, test_s322_fws_around_angle |
| group | 3.4 | Complete including empty group and CFWS-only group-list | test_s34_group_two, test_s34_empty_group, test_s34_group_with_cfws |
| display-name | 3.4 | Complete via phrase | test_s323_comment_in_display, test_s325_phrase_atoms |
| mailbox-list | 3.4 | Complete, rejects group members | test_s34_mailbox_list |
| address-list | 3.4 | Complete for strict lists and permissive null members | test_s34_addr_list_two, test_s44_obs_addr_list_double_comma |
| group-list | 3.4 | Complete for mailbox-list and CFWS-only forms | test_s34_group_two, test_edge_comment_only_group_list |
| addr-spec | 3.4.1 | Complete with top-level at-sign split | test_s34_simple_addr_spec, test_invalid_missing_at |
| local-part | 3.4.1 | Complete for dot-atom, quoted-string, and permissive obs-local-part | test_s34_plus_tag, test_s324_quoted_local_space, test_s44_obs_local_mixed |
| domain | 3.4.1 | Complete for dot-atom, domain-literal, and permissive obs-domain | test_s341_subdomains, test_s341_ipv4_literal, test_s44_obs_domain_trailing_dot |
| domain-literal | 3.4.1 | Complete for IPv4 and IPv6 literals in strict mode | test_s341_ipv4_literal, test_s341_ipv6_literal, test_s341_full_ipv6_literal |
| dtext | 3.4.1 | Complete for strict IP literal payloads and permissive obs-dtext | test_s341_ipv4_literal, test_s341_ipv6_literal |
| obs-angle-addr | 4.4 | Complete in permissive mode, route ignored | test_s44_obs_angle_route |
| obs-route | 4.4 | Complete in permissive mode | test_s44_obs_angle_route |
| obs-domain-list | 4.4 | Complete enough for route discard semantics | test_s44_obs_angle_route |
| obs-mbox-list | 4.4 | Complete in permissive parse_mailbox_list through null-member skipping | test_s44_obs_addr_list_leading_empty, test_s44_obs_addr_list_trailing_empty |
| obs-addr-list | 4.4 | Complete in permissive parse_address_list through null-member skipping | test_s44_obs_addr_list_double_comma |
| obs-group-list | 4.4 | Complete in permissive mode for comma-only group list | test_s44_obs_group_empty_commas |
| obs-local-part | 4.4 | Complete in permissive mode for atom and quoted-string word sequences | test_s44_obs_local_mixed, test_s44_obs_quoted_word_sequence |
| obs-domain | 4.4 | Complete in permissive mode for legacy leading or trailing dot atoms | test_s44_obs_domain_leading_dot, test_s44_obs_domain_trailing_dot |
| obs-dtext | 4.4 | Complete for permissive escaped domain-literal characters | covered by parser branch; strict IP tests prove normal path |

## Verification

`python3 -m unittest -v test_parser.py` discovers and runs 76 cases covering the issue's required minimum of 60 parser tests.
