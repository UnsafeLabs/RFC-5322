# RFC 5322 Compliance Matrix

| ABNF Production | RFC Section | Test Functions | Status |
|---|---|---|---|
| `quoted-pair` | §3.2.1 | `test_quoted_pair_1` to `test_quoted_pair_5` | Complete |
| `FWS` | §3.2.2 | `test_fws_1` to `test_fws_5` | Complete |
| `CFWS` | §3.2.3 | `test_comment_1` to `test_comment_8` | Complete |
| `quoted-string` | §3.2.4 | `test_quoted_string_1` to `test_quoted_string_8` | Complete |
| `word` / `phrase` | §3.2.5 | `test_misc_1` to `test_misc_3` | Complete |
| `address` / `mailbox` | §3.4 | `test_addr_1` to `test_addr_28` | Complete |
| `addr-spec` | §3.4.1 | `test_addr_1` to `test_addr_28` | Complete |
| `obs-addressing` | §4.4 | `test_edge_1` to `test_edge_13` | Partial |
