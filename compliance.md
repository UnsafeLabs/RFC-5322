# RFC 5322 Compliance Matrix — Address Parser

This matrix maps every ABNF production used by the email address parser in
`parser.py` to:

- the RFC 5322 section that defines it,
- the test case(s) in `test_parser.py` that exercise it,
- the implementation status.

Implementation status legend:

- **complete** — production implemented with full semantics
- **partial** — implemented, with documented deviations/liberties
- **N/A** — production is defined by the RFC but not used by address parsing

The parser's public API lives in `AddressParser`: `parse()`,
`parse_address_list()`, and `parse_mailbox_list()`. `strict=True`
implements the §3 "generation" grammar and rejects every `obs-*`
production; `strict=False` additionally accepts the §4 obsolete forms that
a conformant receiver MUST interpret.

---

## §3.2.1 — Quoted characters

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `quoted-pair` | §3.2.1 | complete | `TestQuotedPair` (7 cases) | `AddressParser._consume_quoted_pair` |

## §3.2.2 — Folding White Space and Comments

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `FWS` | §3.2.2 | complete | `TestFWS` (8 cases) | `AddressParser._consume_fws` |
| `ctext` | §3.2.2 | complete | `TestCFWS`, `TestQuotedPair::test_escaped_parens_in_comment` | `_is_ctext` |
| `ccontent` | §3.2.2 | complete | `TestCFWS`, `TestQuotedPair` | `AddressParser._consume_comment` |
| `comment` | §3.2.2 | complete | `TestCFWS` (10 cases) | `AddressParser._consume_comment` |
| `CFWS` | §3.2.2 | complete | `TestCFWS`, `TestEdgeCases::test_leading_and_trailing_fws` | `AddressParser._consume_cfws` |

## §3.2.3 — Atom

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `atext` | §3.2.3 | complete | `TestMiscTokens::test_question_mark_in_atom`, most address tests | module `_ATEXT` |
| `atom` | §3.2.3 | complete | `TestMiscTokens`, `TestAddress` | `AddressParser._parse_atom` |
| `dot-atom-text` | §3.2.3 | complete | `TestAddrSpecDomain` | `AddressParser._parse_dot_atom` |
| `dot-atom` | §3.2.3 | complete | `TestAddrSpecDomain`, `TestInvalid` | `AddressParser._parse_dot_atom` |
| `specials` | §3.2.3 | N/A | — (informational only, not referenced elsewhere in the grammar) | — |

## §3.2.4 — Quoted Strings

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `qtext` | §3.2.4 | complete | `TestQuotedString`, `TestInvalid::test_unterminated_quoted_string` | `_is_qtext` |
| `qcontent` | §3.2.4 | complete | `TestQuotedString` | `AddressParser._parse_quoted_string` |
| `quoted-string` | §3.2.4 | complete | `TestQuotedString` (10 cases) | `AddressParser._parse_quoted_string` |

## §3.2.5 — Miscellaneous Tokens

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `word` | §3.2.5 | complete | `TestMiscTokens` | `AddressParser._parse_word` |
| `phrase` | §3.2.5 | complete (strict); permissive uses `obs-phrase` | `TestMiscTokens` (5 cases) | `AddressParser._parse_display_name` |
| `unstructured` | §3.2.5 | N/A | — (unstructured header field bodies only; not used by address parsing) | — |

## §3.4 — Address Specification

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `address` | §3.4 | complete | `TestAddress` (15 cases) | `AddressParser._parse_address` |
| `mailbox` | §3.4 | complete | `TestAddress`, `TestInvalid` | `AddressParser._parse_mailbox` |
| `name-addr` | §3.4 | complete | `TestAddress::test_name_addr_quoted`, `test_name_addr_phrase` | `AddressParser._parse_mailbox` |
| `angle-addr` | §3.4 | complete | `TestAddress::test_angle_addr_without_display_name` | `AddressParser._parse_angle_addr` |
| `group` | §3.4 | complete | `TestAddress::test_group`, `test_empty_group`, `test_group_list_of_cfws` | `AddressParser._parse_group` |
| `display-name` | §3.4 | complete | `TestMiscTokens`, `TestAddress` | `AddressParser._parse_display_name` |
| `mailbox-list` | §3.4 | complete | `TestAddress::test_mailbox_list`, `TestObsoleteAddressing::test_obs_mbox_list_trailing_comma` | `AddressParser._parse_mailbox_list` |
| `address-list` | §3.4 | complete | `TestAddress::test_address_list*`, `TestObsoleteAddressing` | `AddressParser._parse_address_list` |
| `group-list` | §3.4 | complete | `TestAddress::test_group`, `test_group_list_of_cfws` | `AddressParser._parse_group` |

## §3.4.1 — Addr-Spec Specification

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `addr-spec` | §3.4.1 | complete | `TestAddrSpecDomain` (10 cases) | `AddressParser._parse_addr_spec` |
| `local-part` | §3.4.1 | complete | `TestAddrSpecDomain`, `TestQuotedString` | `AddressParser._parse_local_part` |
| `domain` | §3.4.1 | complete | `TestAddrSpecDomain`, `TestObsoleteAddressing` | `AddressParser._parse_domain` |
| `domain-literal` | §3.4.1 | complete | `TestAddrSpecDomain::test_ipv4_domain_literal` … `test_full_ipv6_domain_literal` | `AddressParser._parse_domain_literal` |
| `dtext` | §3.4.1 | complete | `TestAddrSpecDomain` | `_is_dtext` |

## §4.1 — Miscellaneous Obsolete Tokens

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `obs-NO-WS-CTL` | §4.1 | complete | `TestQuotedString::test_control_char_in_qtext_rejected`, `TestObsoleteAddressing::test_obs_quoted_pair_in_comment` | `_is_no_ws_ctl` |
| `obs-ctext` | §4.1 | complete | `TestQuotedString::test_control_char_in_qtext_rejected` (via `_is_ctext_char`) | `AddressParser._is_ctext_char` |
| `obs-qtext` | §4.1 | complete | `TestQuotedString::test_control_char_in_qtext_rejected` | `AddressParser._is_qtext_char` |
| `obs-qp` | §4.1 | complete | `TestObsoleteAddressing::test_obs_quoted_pair_in_comment` | `AddressParser._consume_quoted_pair` |
| `obs-phrase` | §4.1 | complete | `TestObsoleteAddressing::test_obs_phrase_with_period` | `AddressParser._parse_display_name` |
| `obs-utext`, `obs-body`, `obs-unstruct` | §4.1 | N/A | — (unstructured bodies / non-address syntax) | — |

## §4.2 — Obsolete Folding White Space

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `obs-FWS` | §4.2 | complete | `TestFWS::test_double_fold_requires_obs` | `AddressParser._consume_fws` |

## §4.4 — Obsolete Addressing

| Production | RFC section | Status | Test cases | Implementation |
|-----------|-------------|--------|-----------|----------------|
| `obs-angle-addr` | §4.4 | complete | `TestObsoleteAddressing::test_obs_route_in_angle_addr` | `AddressParser._parse_angle_addr` |
| `obs-route` | §4.4 | complete | `TestObsoleteAddressing::test_obs_route_in_angle_addr`, `test_obs_route_with_multiple_domains` | `AddressParser._parse_obs_route` |
| `obs-domain-list` | §4.4 | complete | `TestObsoleteAddressing::test_obs_route_with_multiple_domains` | `AddressParser._parse_obs_route` |
| `obs-mbox-list` | §4.4 | complete | `TestObsoleteAddressing::test_obs_mbox_list_trailing_comma` | `AddressParser._parse_mailbox_list` |
| `obs-addr-list` | §4.4 | complete | `TestObsoleteAddressing::test_obs_addr_list_null_member`, `test_obs_addr_list_leading_and_trailing_commas`, `test_appendix_obsolete_addressing` | `AddressParser._parse_address_list` |
| `obs-group-list` | §4.4 | complete | `TestObsoleteAddressing::test_obs_group_list_commas` | `AddressParser._parse_group` |
| `obs-local-part` | §4.4 | complete | `TestObsoleteAddressing::test_obs_local_part_mixed` | `AddressParser._parse_obs_local_part` |
| `obs-domain` | §4.4 | partial (liberal: leading/trailing dots tolerated) | `TestObsoleteAddressing::test_obs_domain_leading_dot`, `test_obs_domain_cfws_around_dots` | `AddressParser._parse_obs_domain` |
| `obs-dtext` | §4.4 | complete | `TestAddrSpecDomain::test_backslash_in_domain_literal_strict_rejected` | `AddressParser._is_dtext_char`, `_parse_domain_literal` |

## Obsolete productions not used in address parsing

| Production | RFC section | Status | Reason |
|-----------|-------------|--------|--------|
| `obs-day-of-week`, `obs-day`, `obs-year`, `obs-hour`, `obs-minute`, `obs-second`, `obs-zone` | §4.3 | N/A | Obsolete date/time syntax, out of scope for address parsing |
| `obs-return`, `obs-received`, `obs-*` field forms | §4.5 | N/A | Whole-message / header-field parsing, out of scope |
| `msg-id`, `id-left`, `id-right`, `no-fold-literal` | §3.6.4 | N/A | Message identifiers, not address syntax |

## Deliberate deviations

1. **`obs-domain` leading/trailing dots.** The strict ABNF
   `obs-domain = atom *("." atom)` cannot begin or end with a dot, yet
   real-world mail such as `user@.leading-dot.com` appears in the wild.
   Permissive mode tolerates leading and trailing dots so that receivers
   "MUST not crash on malformed data" (RFC 5322 §4). Strict mode rejects
   them, matching the ABNF exactly.

2. **Comment flattening.** Nested comments are recorded depth-first: each
   nested comment is added to `comments` individually and also appears
   verbatim (parentheses preserved) inside its parent's entry. For
   `(outer(inner))`, `comments == ["inner", "outer(inner)"]` or the
   equivalent set `{"outer(inner)", "inner"}`.

3. **FWS collapse.** Runs of FWS inside quoted-strings, comments, and
   domain literals collapse to a single space character (RFC 5322 §3.2.2).

4. **Route stripping.** The obsolete route portion of an
   `obs-angle-addr` is parsed and discarded, as mandated by RFC 5322 §4.4
   ("the route portion SHOULD be ignored").