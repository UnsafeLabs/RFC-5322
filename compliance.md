# RFC 5322 Compliance Matrix

| ABNF Production | RFC Section | Test Cases | Implementation Status |
|-----------------|-------------|------------|-----------------------|
| `quoted-pair`   | §3.2.1      | `test_quoted_pair_*` | Partial |
| `FWS`           | §3.2.2      | `test_fws_*`         | Partial |
| `CFWS`          | §3.2.3      | `test_cfws_*`        | Partial |
| `quoted-string` | §3.2.4      | `test_quoted_string_*` | Partial |
| `word`          | §3.2.5      | `test_misc_tokens_*` | Partial |
| `address`       | §3.4        | `test_address_*`     | Partial |
| `mailbox`       | §3.4        | `test_address_*`     | Partial |
| `name-addr`     | §3.4        | `test_address_*`     | Partial |
| `angle-addr`    | §3.4        | `test_address_*`     | Partial |
| `group`         | §3.4        | `test_address_*`     | Partial |
| `display-name`  | §3.4        | `test_address_*`     | Partial |
| `mailbox-list`  | §3.4        | `test_address_*`     | Partial |
| `address-list`  | §3.4        | `test_address_*`     | Partial |
| `addr-spec`     | §3.4.1      | `test_addr_spec_*`   | Partial |
| `local-part`    | §3.4.1      | `test_addr_spec_*`   | Partial |
| `domain`        | §3.4.1      | `test_addr_spec_*`   | Partial |
| `domain-literal`| §3.4.1      | `test_addr_spec_*`   | Partial |
| `dcontent`      | §3.4.1      | `test_addr_spec_*`   | Partial |
| `dtext`         | §3.4.1      | `test_addr_spec_*`   | Partial |
| `obs-local-part`| §4.4        | `test_obsolete_*`    | Partial |
| `obs-domain`    | §4.4        | `test_obsolete_*`    | Partial |
| `obs-FWS`       | §4.2        | `test_obsolete_*`    | Partial |
