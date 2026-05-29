# RFC-5322 Parsing Architecture & Gotchas

## Implementation Strategy
The `AddressParser` uses a recursive-descent cursor-based parser model (`ParserState`). It tracks the parsing index linearly through the input string, allowing lookahead and backtracking when distinguishing between different productions (such as separating simple `addr-spec` from `phrase <addr-spec>` name-addr configurations).

## Key Gotchas

### 1. Nested Comments (CFWS)
CFWS can contain comments, which can nest recursively (e.g. `(outer (inner) comment)`). 
- **Gotcha**: A comment cannot be simply stripped; comments must be parsed recursively by tracking bracket balances and extracting them into the `comments` list on the resulting `RFC5322Address`.
- **Solution**: Implemented recursive parsing of comment blocks via `ParserState.parse_comment()`.

### 2. Quoted Pairs inside CFWS and Quoted Strings
Backslash escapes (quoted-pairs) allow escaping characters that are otherwise syntactically significant.
- **Gotcha**: Quoted-pairs behave differently inside and outside strict mode. In strict mode, only VCHAR and WSP (space/tab) characters can be escaped. 
- **Solution**: Validated character bounds during escape sequences and raised `ValueError` under strict mode when invalid characters are escaped.

### 3. Mixed Dot-Atom and Quoted-String in Obsolete Local Part
Per section 4.4, obsolete local parts (`obs-local-part`) allow mixing dots and quoted strings together, e.g., `user."quoted"@example.com`.
- **Gotcha**: A simple split or regular expression cannot parse this because of quoting and comment folding.
- **Solution**: The parser splits components using a loop that consumes dot-atoms and quoted-strings sequentially and handles their comment fields cleanly.

### 4. Line Length Constraints
RFC 5322 specifies a strict line length limit of 998 characters (excluding CRLF).
- **Gotcha**: Inputs longer than 998 characters must be rejected in strict mode.
- **Solution**: Added length checking validation in `AddressParser.parse()`, `parse_address_list()`, and `parse_mailbox_list()`.
