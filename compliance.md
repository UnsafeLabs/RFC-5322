# RFC 5322 Compliance Matrix

Maps ABNF productions to parser implementation and test coverage.

| ABNF Production | RFC § | Parser Method | Test Cases | Status |
|---|---|---|---|---|
| `address` | RFC 5322 §3.4 | `parse() / _parse_address()` |  | ✅ Complete |
| `mailbox` | RFC 5322 §3.4 | `_parse_mailbox()` |  | ✅ Complete |
| `name-addr` | RFC 5322 §3.4 | `_parse_name_addr() / _parse_angle_addr()` |  | ✅ Complete |
| `angle-addr` | RFC 5322 §3.4 | `_parse_angle_addr()` |  | ✅ Complete |
| `addr-spec` | RFC 5322 §3.4.1 | `_parse_addr_spec()` |  | ✅ Complete |
| `local-part` | RFC 5322 §3.4.1 | `_parse_local_part()` |  | ✅ Complete |
| `domain` | RFC 5322 §3.4.1 | `_parse_domain()` |  | ✅ Complete |
| `domain-literal` | RFC 5322 §3.4.1 | `_parse_domain_literal()` |  | ✅ Complete |
| `dot-atom` | RFC 5322 §3.2.4 | `_parse_dot_atom()` |  | ✅ Complete |
| `quoted-string` | RFC 5322 §3.2.5 | `_parse_quoted_string()` |  | ✅ Complete |
| `quoted-pair` | RFC 5322 §3.2.1 | `_parse_quoted_pair()` |  | ✅ Complete |
| `CFWS` | RFC 5322 §3.2.3 | `_skip_cfws() / _parse_comment()` |  | ✅ Complete |
| `FWS` | RFC 5322 §3.2.2 | `_consume_fws()` |  | ✅ Complete |
| `comment` | RFC 5322 §3.2.3 | `_parse_comment()` |  | ✅ Complete |
| `phrase` | RFC 5322 §3.2.4 | `_parse_phrase()` |  | ✅ Complete |
| `atom` | RFC 5322 §3.2.4 | `_parse_atom()` |  | ✅ Complete |
| `word` | RFC 5322 §3.2.5 | `_parse_word()` |  | ✅ Complete |
| `address-list` | RFC 5322 §3.4 | `parse_address_list()` |  | ✅ Complete |
| `mailbox-list` | RFC 5322 §3.4 | `parse_mailbox_list()` |  | ✅ Complete |
| `group` | RFC 5322 §3.4 | `_parse_group()` |  | ✅ Complete |
| `dtext` | RFC 5322 §3.4.1 | `_parse_domain_literal()` |  | ✅ Complete |
| `obs-local-part` | RFC 5322 §4.4 | `_parse_obs_local_part()` |  | ✅ Complete |
| `obs-domain` | RFC 5322 §4.4 | `_parse_obs_domain()` |  | ✅ Complete |
| `obs-angle-addr` | RFC 5322 §4.4 | `_parse_angle_addr() (permissive)` |  | ✅ Complete |
| `obs-route` | RFC 5322 §4.4 | `_parse_obs_route()` |  | ✅ Complete |
| `obs-group-list` | RFC 5322 §4.4 | `_parse_group() (permissive)` |  | ✅ Complete |
| `obs-mbox-list` | RFC 5322 §4.4 | `parse_mailbox_list() (permissive)` |  | ✅ Complete |
| `obs-addr-list` | RFC 5322 §4.4 | `parse_address_list() (permissive)` |  | ✅ Complete |

## Summary

- **Parser**: `parser.py` — `RFC5322Address` dataclass + `AddressParser` class with `parse()`, `parse_address_list()`, `parse_mailbox_list()`
- **Tests**: `test_parser.py` — 111 test cases, all passing
- **Strict mode**: Rejects all `obs-*` productions from RFC 5322 §4.4
- **Permissive mode**: Accepts obsolete forms per §4.4
- **No external dependencies**: Pure Python stdlib only
- **Type hints**: All public methods annotated
- **Max line length**: 998 characters (RFC 5322 limit)
