# RFC 5322 Address Parser Compliance Matrix

This matrix covers the ABNF productions used by address parsing from RFC 5322
sections 3.2-3.4.1 and obsolete addressing from section 4.4.

| Production | RFC section | Implementation | Tests |
| --- | --- | --- | --- |
| `quoted-pair` | §3.2.1 | Complete: `_Cursor._quoted_pair` handles escaped VCHAR/WSP in strict mode and obs controls in permissive mode. | `TestQuotedPair321` |
| `FWS` | §3.2.2 | Complete: `_Cursor._skip_fws` consumes WSP and CRLF-folded WSP wherever CFWS or quoted/domain content permits it. | `TestFWS322`, `test_fws_inside_domain_literal` |
| `CFWS` | §3.2.2 | Complete: `_Cursor.skip_cfws` handles repeated FWS and nested comments. | `TestCFWSAndComments323`, `test_comments_do_not_change_addr_spec_values` |
| `comment` | §3.2.2 | Complete: `_Cursor._comment` handles nesting, quoted-pairs, and unterminated rejection. | `test_nested_comments`, `test_deeply_nested_comments`, `test_rejects_unclosed_comment` |
| `ccontent` | §3.2.2 | Complete for address parsing: comments accept ctext, quoted-pair, and nested comment. | `TestCFWSAndComments323` |
| `ctext` | §3.2.2 | Complete for ASCII ctext ranges; strict mode rejects invalid controls. | `test_rejects_unclosed_comment`, `test_rejects_strict_escaped_control` |
| `atext` | §3.2.3 | Complete: `ATEXT` contains the RFC atext character set. | `test_atom_with_allowed_atext_symbols` |
| `atom` | §3.2.3 | Complete: `_atom` parses `[CFWS] 1*atext [CFWS]`. | `test_phrase_combines_words`, `TestCFWSAndComments323` |
| `dot-atom` | §3.2.3 | Complete: `_dot_atom` parses `[CFWS] dot-atom-text [CFWS]`. | `test_simple_addr_spec`, `test_dot_atom_domain`, invalid consecutive-dot tests |
| `dot-atom-text` | §3.2.3 | Complete: `_dot_atom` uses `_atext_run` around literal dots. | `test_dot_atom_domain`, `test_rejects_consecutive_dots_in_domain` |
| `qtext` | §3.2.4 | Complete: `_quoted_string` accepts RFC qtext printable ranges. | `TestQuotedString324` |
| `qcontent` | §3.2.4 | Complete: `_quoted_string` accepts qtext and quoted-pair, with FWS. | `test_all_specials_inside_quoted_string`, `test_escaped_quote_in_local_part` |
| `quoted-string` | §3.2.4 | Complete: `_quoted_string` parses `[CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]`. | `TestQuotedString324` |
| `word` | §3.2.5 | Complete: `_word` dispatches `atom / quoted-string`. | `test_phrase_combines_words`, `test_quoted_display_name` |
| `phrase` | §3.2.5 | Complete for address display names; permissive mode accepts obs phrase dots. | `test_phrase_combines_words`, `test_name_addr` |
| `display-name` | §3.4 | Complete: `_name_addr` parses optional phrase before `angle-addr`. | `test_name_addr`, `test_quoted_display_name` |
| `mailbox` | §3.4 | Complete: `_mailbox` parses `name-addr / addr-spec`. | `test_simple_addr_spec`, `test_name_addr` |
| `name-addr` | §3.4 | Complete: `_name_addr` parses optional display name and angle address. | `test_name_addr`, `test_angle_addr_without_display_name` |
| `angle-addr` | §3.4 | Complete in strict mode and obs route-aware in permissive mode. | `test_angle_addr_without_display_name`, `test_obs_angle_route` |
| `group` | §3.4 | Complete: `_group` parses `display-name ":" [group-list] ";" [CFWS]`. | `test_address_group`, `test_empty_group`, `test_obs_group_list_commas` |
| `group-list` | §3.4 | Complete: strict mailbox lists and CFWS-only empty groups; obs comma-only groups in permissive mode. | `test_empty_group`, `test_obs_group_list_commas` |
| `address` | §3.4 | Complete: `_address` dispatches `mailbox / group`. | `test_parse_address_list_with_group_and_mailbox` |
| `mailbox-list` | §3.4 | Complete: `parse_mailbox_list` parses comma-separated mailboxes and rejects groups. | `test_parse_mailbox_list`, `test_mailbox_list_rejects_group` |
| `address-list` | §3.4 | Complete: `parse_address_list` parses comma-separated addresses, including groups. | `test_parse_address_list_with_group_and_mailbox`, obs list tests |
| `addr-spec` | §3.4.1 | Complete: `_addr_spec` parses `local-part "@" domain`. | `test_simple_addr_spec`, `TestAddrSpecAndDomainLiteral341` |
| `local-part` | §3.4.1 | Complete: dot-atom, quoted-string, or obs-local-part in permissive mode. | `test_simple_addr_spec`, `test_simple_quoted_local_part`, `test_obs_local_part_mixes_atom_and_quoted_string` |
| `domain` | §3.4.1 | Complete: dot-atom, domain-literal, or obs-domain in permissive mode. | `test_dot_atom_domain`, `test_ipv4_domain_literal`, `test_obs_domain_leading_dot` |
| `domain-literal` | §3.4.1 | Complete: `_domain_literal` parses bracketed dtext/FWS and validates IPv4/IPv6 address literals when the content uses those forms. | `TestAddrSpecAndDomainLiteral341` |
| `dtext` | §3.4.1 | Complete for strict dtext ranges; quoted obs dtext is accepted only in permissive mode. | `test_general_domain_literal`, `test_rejects_unclosed_domain_literal` |
| `obs-angle-addr` | §4.4 | Complete in permissive mode: `_obs_route` ignores obsolete source route and parses the final addr-spec. | `test_obs_angle_route`, `test_strict_rejects_obs_angle_route` |
| `obs-route` | §4.4 | Complete for address parsing: parsed and discarded as obsolete routing metadata. | `test_obs_angle_route` |
| `obs-domain-list` | §4.4 | Complete for route parsing: repeated `@domain` separated by commas/CFWS. | `test_obs_angle_route` |
| `obs-mbox-list` | §4.4 | Complete in permissive mode through `parse_mailbox_list` empty-element handling. | `test_obs_address_list_leading_empty_member`, `test_obs_address_list_trailing_empty_member` |
| `obs-addr-list` | §4.4 | Complete in permissive mode through `parse_address_list` empty-element handling. | `test_obs_address_list_leading_empty_member`, `test_obs_address_list_trailing_empty_member` |
| `obs-group-list` | §4.4 | Complete in permissive mode for comma-only group list gaps. | `test_obs_group_list_commas` |
| `obs-local-part` | §4.4 | Complete in permissive mode: `_obs_local_part` parses `word *("." word)`. | `test_obs_local_part_mixes_atom_and_quoted_string` |
| `obs-domain` | §4.4 | Complete in permissive mode: `_obs_domain` accepts atom-dot forms rejected by strict dot-atom. | `test_obs_domain_leading_dot` |
| `obs-dtext` | §4.4 | Complete in permissive domain literals through quoted-pair support when `strict=False`. | `TestAddrSpecAndDomainLiteral341`, permissive parser branch |

## Notes

- Public methods are typed and return `RFC5322Address` instances.
- Strict mode rejects the obsolete productions covered by §4.4 tests.
- Parsed `local_part` and `display_name` use semantic text: surrounding quotes,
  quoted-pair escapes, comments, and folded CRLF are removed.
- `domain-literal` preserves brackets in the returned `domain` so callers can
  distinguish literals from dot-atom domains.
