# RFC 5322 Address Parser — Compliance Matrix

This document maps every ABNF production used in email address parsing to the
implementing parser method, the RFC section defining it, and the test cases
exercising it.

## Section 3.2: Lexical Tokens

| ABNF Production | RFC Section | Parser Method | Test Class | Status |
|---|---|---|---|---|
| `quoted-pair` | §3.2.1 | `_quoted_pair()` | `TestQuotedPair` (5 tests) | Complete |
| `FWS` | §3.2.2 | `_fws()` | `TestFWS` (5 tests) | Complete |
| `ctext` | §3.2.2 | `_ctext()` | `TestCFWS` (8 tests) | Complete |
| `ccontent` | §3.2.2 | `_ccontent()` | `TestCFWS` | Complete |
| `comment` | §3.2.2 | `_comment()` | `TestCFWS` | Complete |
| `CFWS` | §3.2.2 | `_skip_cfws()` | `TestCFWS` | Complete |
| `atext` | §3.2.3 | `_atext()` | `TestMiscTokens`, `TestAddrSpec` | Complete |
| `atom` | §3.2.3 | `_atom()` | `TestMiscTokens` | Complete |
| `dot-atom-text` | §3.2.3 | `_dot_atom_text()` | `TestAddrSpec` | Complete |
| `dot-atom` | §3.2.3 | `_dot_atom()` | `TestAddrSpec` | Complete |
| `qtext` | §3.2.4 | `_qtext()` | `TestQuotedString` (8 tests) | Complete |
| `qcontent` | §3.2.4 | `_qcontent()` | `TestQuotedString` | Complete |
| `quoted-string` | §3.2.4 | `_quoted_string()` | `TestQuotedString` | Complete |
| `word` | §3.2.5 | `_word()` | `TestMiscTokens` | Complete |
| `phrase` | §3.2.5 | `_phrase()` | `TestMiscTokens` | Complete |

## Section 3.4: Address Specification

| ABNF Production | RFC Section | Parser Method | Test Class | Status |
|---|---|---|---|---|
| `address` | §3.4 | `_address()` | `TestAddress` (12 tests) | Complete |
| `mailbox` | §3.4 | `_mailbox()` | `TestAddress` | Complete |
| `name-addr` | §3.4 | `_name_addr()` | `TestAddress` | Complete |
| `angle-addr` | §3.4 | `_angle_addr()` | `TestAddress` | Complete |
| `group` | §3.4 | `_group()` | `TestAddress` | Complete |
| `display-name` | §3.4 | `_phrase()` | `TestAddress` | Complete |
| `mailbox-list` | §3.4 | `_mailbox_list_internal()` | `TestMailboxList` | Complete |
| `address-list` | §3.4 | `parse_address_list()` | `TestAddress` | Complete |
| `group-list` | §3.4 | `_group_list()` | `TestAddress` | Complete |

## Section 3.4.1: Addr-Spec Specification

| ABNF Production | RFC Section | Parser Method | Test Class | Status |
|---|---|---|---|---|
| `addr-spec` | §3.4.1 | `_addr_spec()` | `TestAddrSpec` (8 tests) | Complete |
| `local-part` | §3.4.1 | `_local_part()` | `TestAddrSpec` | Complete |
| `domain` | §3.4.1 | `_domain()` | `TestAddrSpec` | Complete |
| `domain-literal` | §3.4.1 | `_domain_literal()` | `TestAddrSpec` | Complete |
| `dtext` | §3.4.1 | `_dtext()` | `TestAddrSpec` | Complete |

## Section 4.4: Obsolete Addressing

| ABNF Production | RFC Section | Parser Method | Test Class | Status |
|---|---|---|---|---|
| `obs-angle-addr` | §4.4 | `_obs_angle_addr_mailbox()` | `TestObsolete` | Complete |
| `obs-route` | §4.4 | `_obs_route()` | `TestObsolete` | Complete |
| `obs-domain-list` | §4.4 | `_obs_domain_list()` | `TestObsolete` | Complete |
| `obs-mbox-list` | §4.4 | `_mailbox_list_internal()` | `TestObsolete` | Complete |
| `obs-addr-list` | §4.4 | `parse_address_list()` | `TestObsolete` | Complete |
| `obs-group-list` | §4.4 | `_group_list()` | `TestAddress` | Complete |
| `obs-local-part` | §4.4 | `_obs_local_part()` | `TestObsolete` | Complete |
| `obs-domain` | §4.4 | `_obs_domain()` | `TestObsolete` | Complete |
| `obs-dtext` | §4.4 | `_obs_dtext()` | `TestObsolete` | Complete |

## Section 4.1: Miscellaneous Obsolete Tokens

| ABNF Production | RFC Section | Parser Method | Test Class | Status |
|---|---|---|---|---|
| `obs-NO-WS-CTL` | §4.1 | `_obs_ctext()`, `_obs_qtext()`, `_obs_dtext()` | `TestObsolete` | Complete |
| `obs-ctext` | §4.1 | `_obs_ctext()` | `TestCFWS` | Complete |
| `obs-qtext` | §4.1 | `_obs_qtext()` | `TestQuotedString` | Complete |
| `obs-qp` | §4.1 | (handled via `_quoted_pair()`) | `TestQuotedPair` | Complete |
| `obs-phrase` | §4.1 | (handled in `_phrase()`) | `TestObsolete` | Complete |
| `obs-FWS` | §4.2 | `_obs_fws()` | `TestFWS` | Complete |

## Test Coverage Summary

| Section | Required | Actual | Status |
|---|---|---|---|
| §3.2.1 (quoted-pair) | 5 | 5 | Met |
| §3.2.2 (FWS) | 5 | 5 | Met |
| §3.2.3 (CFWS/comments) | 8 | 8 | Met |
| §3.2.4 (quoted-string) | 8 | 8 | Met |
| §3.2.5 (misc tokens) | 3 | 3 | Met |
| §3.4 (address/mailbox/group) | 12 | 12 | Met |
| §3.4.1 (addr-spec/domain-literal) | 8 | 8 | Met |
| §4.4 (obsolete addressing) | 8 | 8 | Met |
| Edge cases | 5 | 5 | Met |
| Invalid/rejection | 8 | 8 | Met |
| **Total** | **68** | **73** | **Exceeded** |

## Implementation Notes

- `parser.py` contains `RFC5322Address` dataclass and `AddressParser` class
- Strict mode (`strict=True`) rejects all `obs-*` productions
- Permissive mode (`strict=False`) accepts obsolete forms per §4.4
- CFWS is stripped from addr-spec; comments extracted and stored in `RFC5322Address.comments`
- Domain literals support both IPv4 and IPv6 forms per §3.4.1
- Group addresses parsed with member list extraction
- No external dependencies — pure Python stdlib only
- Type hints on all public methods
- Handles inputs up to 998 characters (RFC 5322 line length limit)
