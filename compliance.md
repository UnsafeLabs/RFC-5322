# RFC 5322 Address Parser — Compliance Matrix

Maps every ABNF production used in address parsing to its RFC section,
exercising test case(s), and implementation status.

| ABNF production | RFC section | Test case(s) | Status |
|-----------------|-------------|--------------|--------|
| `quoted-pair` | §3.2.1 | `TestQuotedPair_3_2_1.*` | complete |
| `obs-qp` | §4.1 / §3.2.1 | permissive path in `_try_quoted_pair` | complete |
| `FWS` | §3.2.2 | `TestFWS_3_2_2.*` | complete |
| `obs-FWS` | §4.2 | covered via permissive FWS folding | partial |
| `ctext` | §3.2.2 | `TestCFWSComments_3_2_3.*` | complete |
| `obs-ctext` | §4.1 | permissive comment path | complete |
| `ccontent` | §3.2.2 | nested + quoted-pair comment tests | complete |
| `comment` | §3.2.2 | `test_nested_comments`, `test_leading_comment` | complete |
| `CFWS` | §3.2.2 | `TestCFWSComments_3_2_3.*`, FWS tests | complete |
| `atext` | §3.2.3 | `test_atext_specials_in_local`, simple addr-spec | complete |
| `atom` | §3.2.3 | phrase/display-name tests | complete |
| `dot-atom-text` | §3.2.3 | `test_dot_atom_local`, domain tests | complete |
| `dot-atom` | §3.2.3 | `test_simple_addr_spec`, domain tests | complete |
| `specials` | §3.2.3 | used as complement of atext (lexer) | complete |
| `qtext` | §3.2.4 | `TestQuotedString_3_2_4.*` | complete |
| `obs-qtext` | §4.1 | permissive quoted-string path | complete |
| `qcontent` | §3.2.4 | quoted-pair + qtext mix tests | complete |
| `quoted-string` | §3.2.4 | `TestQuotedString_3_2_4.*` | complete |
| `word` | §3.2.5 | `TestMiscTokens_3_2_5.*`, obs-local-part | complete |
| `phrase` | §3.2.5 | display-name / group name tests | complete |
| `obs-phrase` | §4.1 | multi-word phrase path | partial |
| `address` | §3.4 | `TestAddressMailboxGroup_3_4.*` | complete |
| `mailbox` | §3.4 | name-addr and addr-spec tests | complete |
| `name-addr` | §3.4 | `test_name_addr`, display-name tests | complete |
| `angle-addr` | §3.4 | `test_angle_addr_only`, name-addr tests | complete |
| `group` | §3.4 | `test_group_*` | complete |
| `display-name` | §3.4 | phrase-based display tests | complete |
| `mailbox-list` | §3.4 | `test_mailbox_list_two`, `parse_mailbox_list` | complete |
| `address-list` | §3.4 | `test_address_list_mixed` | complete |
| `group-list` | §3.4 | empty and non-empty group tests | complete |
| `addr-spec` | §3.4.1 | `TestAddrSpecDomainLiteral_3_4_1.*` | complete |
| `local-part` | §3.4.1 | dot-atom / quoted / obs-local tests | complete |
| `domain` | §3.4.1 | dot-atom / literal / obs-domain tests | complete |
| `domain-literal` | §3.4.1 | IPv4/IPv6 literal tests | complete |
| `dtext` | §3.4.1 | domain-literal content tests | complete |
| `obs-dtext` | §4.4 | permissive domain-literal path | complete |
| `obs-angle-addr` | §4.4 | `test_obs_route_permissive` | complete |
| `obs-route` | §4.4 | `test_obs_route_permissive` | complete |
| `obs-domain-list` | §4.4 | route tests | complete |
| `obs-mbox-list` | §4.4 | `test_obs_mbox_list_null_members` | complete |
| `obs-addr-list` | §4.4 | permissive `parse_address_list` null members | complete |
| `obs-group-list` | §4.4 | empty group / CFWS-only group-list | complete |
| `obs-local-part` | §4.4 | `test_obs_local_mixed_permissive` | complete |
| `obs-domain` | §4.4 | `test_obs_domain_leading_dot_permissive` | complete |

## Mode behavior

| Mode | Behavior |
|------|----------|
| `strict=True` (default) | Rejects all `obs-*` productions used in addressing |
| `strict=False` | Accepts §4.4 obsolete forms (routes, mixed local-part, null list members, leading-dot domains) |

## Limits

| Constraint | Implementation |
|------------|----------------|
| Line length ≤ 998 (§2.1.1) | `AddressParser.MAX_LENGTH`; `test_max_length_998`, `test_over_max_length_rejected` |
| Pure Python stdlib | No third-party imports |
| Type hints | Public methods and `RFC5322Address` annotated |
