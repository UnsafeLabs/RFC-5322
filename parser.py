"""
RFC 5322 compliant email address parser.

Implements the full ABNF grammar from §3.2-§3.4 with optional
obsolete syntax support from §4.4.

No external dependencies — pure Python stdlib only.

Reference: https://tools.ietf.org/html/rfc5322
"""

import re
from dataclasses import dataclass, field
from typing import Optional

# ─── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address (mailbox or group)."""
    display_name: Optional[str] = None
    local_part: str = ""
    domain: str = ""
    is_group: bool = False
    group_members: list['RFC5322Address'] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""

    def __repr__(self):
        if self.is_group:
            members = ", ".join(repr(m) for m in self.group_members)
            return (f"RFC5322Address(display_name={self.display_name!r}, "
                    f"is_group=True, members=[{members}], "
                    f"comments={self.comments!r}, source={self.source!r})")
        return (f"RFC5322Address(display_name={self.display_name!r}, "
                f"local_part={self.local_part!r}, domain={self.domain!r}, "
                f"is_group={self.is_group}, comments={self.comments!r}, "
                f"source={self.source!r})")


# ─── Token Types ─────────────────────────────────────────────────────────────

class TokenType:
    ATOM = "ATOM"
    DOT = "DOT"
    AT = "AT"
    LT = "LT"
    GT = "GT"
    COLON = "COLON"
    SEMICOLON = "SEMICOLON"
    COMMA = "COMMA"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    QUOTED_STRING = "QUOTED_STRING"
    COMMENT = "COMMENT"
    FWS = "FWS"
    CFWS = "CFWS"
    EOF = "EOF"


# ─── Token Class ─────────────────────────────────────────────────────────────

@dataclass
class Token:
    type: str
    value: str
    comments: list[str] = field(default_factory=list)

    def __repr__(self):
        return f"Token({self.type}, {self.value!r})"


# ─── Lexer ───────────────────────────────────────────────────────────────────

class RFC5322Lexer:
    """Lexer for RFC 5322 address tokens.
    
    Implements lexical analysis per §3.2:
    - §3.2.1: quoted-pair — backslash-escaped character
    - §3.2.2: FWS — folding white space
    - §3.2.3: CFWS — comments and folding white space
    - §3.2.4: quoted-string — double-quoted string with quoted-pairs
    - §3.2.5: Miscellaneous tokens (atoms, specials, domain literals)
    - §4.1: obs-FWS, obs-ctext, obs-qp, obs-qtext
    """

    # §3.2.3 atext: printable US-ASCII characters except specials
    _ATEXT = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]")

    # §3.2.3 dot-atom-text: 1*atext *("." 1*atext)
    _DOT_ATOM = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")

    # §3.2.4 obs-qtext per §4.1
    _OBS_QTEXT = re.compile(r"[\x01-\x09\x0b\x0c\x0e-\x1f\x7f]")

    # §4.1 obs-ctext
    _OBS_CTEXT = re.compile(r"[\x01-\x09\x0b\x0c\x0e-\x1f\x7f]")

    def __init__(self, text: str, strict: bool = True):
        self.text = text
        self.pos = 0
        self.strict = strict
        self.comments_buffer: list[str] = []

    def eof(self) -> bool:
        return self.pos >= len(self.text)

    def peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        return self.text[idx] if idx < len(self.text) else ""

    def advance(self, n: int = 1):
        self.pos += n

    def skip_spaces(self):
        """Skip SP and HTAB after CFWS/FWS processing."""
        while self.pos < len(self.text) and self.text[self.pos] in (' ', '\t'):
            self.pos += 1

    # ── §3.2.1 quoted-pair ───────────────────────────────────────────────
    def read_quoted_pair(self, obs: bool = False) -> Optional[str]:
        """Read a quoted-pair: backslash followed by any character.
        
        In strict mode (§3.2.1): backslash + any ASCII graphic or SP/HTAB
        In obs mode (§4.1): backslash + any ASCII character
        """
        if self.peek() != '\\':
            return None
        next_ch = self.peek(1)
        if not next_ch:
            return None
        if self.strict and not obs:
            # §3.2.1: quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
            # VCHAR = 0x21-0x7E, WSP = SP / HTAB
            cp = ord(next_ch)
            if not ((0x21 <= cp <= 0x7E) or cp in (0x20, 0x09)):
                return None
        else:
            # obs-qp: any ASCII character
            cp = ord(next_ch)
            if cp > 127:
                return None
        self.advance(2)
        return next_ch

    # ── §3.2.4 quoted-string ─────────────────────────────────────────────
    def read_quoted_string(self) -> Optional[str]:
        """Read a quoted-string per §3.2.4.
        
        quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
        qcontent = qtext / quoted-pair
        
        Returns the raw content inside the quotes (qcontent).
        """
        start = self.pos
        # Leading CFWS
        self.read_cfws()
        if self.peek() != '"':
            self.pos = start
            return None
        self.advance()  # skip opening DQUOTE
        result: list[str] = []
        while not self.eof():
            # §3.2.4: *([FWS] qcontent) — FWS can appear anywhere in quotes
            if self.peek() in (' ', '\t', '\r', '\n'):
                fws_consumed = self.read_fws()
                # Normalize FWS to a single space inside quotes
                if fws_consumed and result:
                    result.append(' ')
                # After FWS, check if we're at the closing quote
                if self.peek() == '"':
                    break
                continue
            ch = self.peek()
            if ch == '"':
                break
            if ch == '\\':
                qp = self.read_quoted_pair(obs=not self.strict)
                if qp is not None:
                    result.append(qp)
                    continue
                # If strict and not valid, include the backslash
                result.append('\\')
                self.advance()
                continue
            # qtext: any ASCII printable except \ and "
            cp = ord(ch)
            if cp == 0x22:  # DQUOTE
                break
            if cp == 0x5c:  # backslash
                qp = self.read_quoted_pair(obs=not self.strict)
                if qp:
                    result.append(qp)
                continue
            # §3.2.4: qtext = %d33 / %d35-91 / %d93-126 / obs-qtext
            if cp == 0x21 or (0x23 <= cp <= 0x5b) or (0x5d <= cp <= 0x7e):
                result.append(ch)
                self.advance()
            elif not self.strict:
                # obs-qtext per §4.1
                if 1 <= cp <= 9 or cp == 11 or cp == 12 or (14 <= cp <= 31) or cp == 127:
                    result.append(ch)
                    self.advance()
                else:
                    break
            else:
                break
        # §3.2.4: [FWS] DQUOTE — trailing FWS before closing quote
        if self.peek() in (' ', '\t', '\r', '\n'):
            self.read_fws()
        if self.peek() != '"':
            self.pos = start
            return None
        self.advance()  # skip closing DQUOTE
        # Trailing CFWS
        self.read_cfws()
        return ''.join(result)

    # ── §3.2.2 FWS ───────────────────────────────────────────────────────
    def read_fws(self) -> bool:
        """Read folding white space per §3.2.2.
        
        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        obs-FWS = 1*WSP *(CRLF 1*WSP)
        """
        marked = self.pos
        # obs-FWS: 1*WSP at minimum
        if not self.strict:
            wsp_count = 0
            while self.peek() in (' ', '\t'):
                self.advance()
                wsp_count += 1
            if wsp_count > 0:
                return True

        # Standard FWS: optional WSP* CRLF + 1*WSP
        had_wsp_before = False
        while self.peek() in (' ', '\t'):
            self.advance()
            had_wsp_before = True
        if self.peek() == '\r':
            self.advance()
            if self.peek() == '\n':
                self.advance()
        # Must have at least 1 WSP after optional CRLF
        if self.peek() in (' ', '\t'):
            while self.peek() in (' ', '\t'):
                self.advance()
            return True
        if had_wsp_before:
            return True
        if not self.strict and self.peek() in (' ', '\t'):
            while self.peek() in (' ', '\t'):
                self.advance()
            return True
        self.pos = marked
        return False

    # ── §3.2.3 CFWS ──────────────────────────────────────────────────────
    def read_comment(self) -> Optional[str]:
        """Read a comment per §3.2.3.
        
        comment = "(" *([FWS] ccontent) [FWS] ")"
        ccontent = ctext / quoted-pair / comment (nested!)
        """
        if self.peek() != '(':
            return None
        self.advance()  # skip '('
        parts: list[str] = []
        depth = 1
        while depth > 0 and not self.eof():
            ch = self.peek()
            if ch == '(':
                depth += 1
                parts.append(ch)
                self.advance()
            elif ch == ')':
                depth -= 1
                if depth > 0:
                    parts.append(ch)
                self.advance()
            elif ch == '\\':
                qp = self.read_quoted_pair(obs=not self.strict)
                if qp:
                    parts.append(qp)
                else:
                    parts.append(ch)
                    self.advance()
            elif ch in ('\r', '\n'):
                self.read_fws()
                parts.append(' ')  # normalize FWS to space in comment content
            else:
                cp = ord(ch)
                # ctext: %d33-39 / %d42-91 / %d93-126 / obs-ctext
                if (0x21 <= cp <= 0x27) or (0x2a <= cp <= 0x5b) or (0x5d <= cp <= 0x7e):
                    parts.append(ch)
                    self.advance()
                elif not self.strict and ((1 <= cp <= 9) or cp == 11 or cp == 12 or (14 <= cp <= 31) or cp == 127):
                    parts.append(ch)
                    self.advance()
                else:
                    parts.append(ch)
                    self.advance()
        return ''.join(parts).strip()

    def read_cfws(self) -> bool:
        """Read CFWS per §3.2.3.
        
        CFWS = (1*([FWS] comment) [FWS]) / FWS
        
        Returns True if any CFWS was consumed.
        """
        consumed = False
        while True:
            marked = self.pos
            # Try ([FWS] comment)
            self.read_fws()
            comment = self.read_comment()
            if comment is not None:
                self.comments_buffer.append(comment)
                consumed = True
                self.read_fws()
                continue
            self.pos = marked
            # Try just FWS
            if self.read_fws():
                consumed = True
            break
        return consumed

    # ── Tokenizer ────────────────────────────────────────────────────────
    def next_token(self) -> Token:
        """Return the next token from the input."""
        # Consume leading CFWS
        self.read_cfws()
        comments = list(self.comments_buffer)
        self.comments_buffer.clear()

        if self.eof():
            return Token(TokenType.EOF, "", comments)

        ch = self.peek()
        
        # Specials (§3.2.5)
        if ch == '<':
            self.advance()
            return Token(TokenType.LT, "<", comments)
        if ch == '>':
            self.advance()
            return Token(TokenType.GT, ">", comments)
        if ch == '@':
            self.advance()
            return Token(TokenType.AT, "@", comments)
        if ch == ':':
            self.advance()
            return Token(TokenType.COLON, ":", comments)
        if ch == ';':
            self.advance()
            return Token(TokenType.SEMICOLON, ";", comments)
        if ch == ',':
            self.advance()
            return Token(TokenType.COMMA, ",", comments)
        if ch == '.':
            self.advance()
            return Token(TokenType.DOT, ".", comments)

        # Domain literal: [dtext / quoted-pair]+
        if ch == '[':
            content = self._read_domain_literal()
            if content is not None:
                return Token(TokenType.LBRACKET, content, comments)

        # Quoted string
        qs = self.read_quoted_string()
        if qs is not None:
            return Token(TokenType.QUOTED_STRING, qs, comments)

        # Atom / dot-atom
        atom = self._read_atom()
        if atom:
            return Token(TokenType.ATOM, atom, comments)

        # Skip any character we can't handle (should not happen for valid input)
        self.advance()
        return Token(TokenType.ATOM, ch, comments)

    def _read_domain_literal(self) -> Optional[str]:
        """Read a domain-literal (§3.4.1): "[" *([FWS] dtext) [FWS] "]".
        
        dtext = %d33-90 / %d94-126 / obs-dtext
        obs-dtext = obs-NO-WS-CTL / quoted-pair
        """
        if self.peek() != '[':
            return None
        start = self.pos
        self.advance()  # skip '['
        parts: list[str] = []
        while not self.eof():
            ch = self.peek()
            if ch == ']':
                break
            if ch == '\\':
                qp = self.read_quoted_pair(obs=not self.strict)
                if qp:
                    parts.append(qp)
                    continue
                parts.append(ch)
                self.advance()
                continue
            if ch in ('\r', '\n'):
                self.read_fws()
                continue
            cp = ord(ch)
            # dtext: %d33-90 / %d94-126
            if (0x21 <= cp <= 0x5a) or (0x5e <= cp <= 0x7e):
                parts.append(ch)
                self.advance()
            elif not self.strict:
                # obs-NO-WS-CTL: %d1-8 / %d11 / %d12 / %d14-31 / %d127
                if (1 <= cp <= 8) or cp == 11 or cp == 12 or (14 <= cp <= 31) or cp == 127:
                    parts.append(ch)
                    self.advance()
                else:
                    break
            else:
                break
        if self.peek() != ']':
            self.pos = start
            return None
        self.advance()  # skip ']'
        return ''.join(parts)

    def _read_atom(self) -> str:
        """Read an atom or dot-atom per §3.2.3."""
        result: list[str] = []
        while not self.eof():
            ch = self.peek()
            if ch in ('<', '>', '@', ':', ';', ',', '.', '[', ']', '(', ')', '"', '\\', '\r', '\n', ' ', '\t'):
                break
            cp = ord(ch)
            # atext: %d33-126 except specials
            if (0x21 <= cp <= 0x7e) and ch not in ('(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '.', '[', ']'):
                result.append(ch)
                self.advance()
            elif not self.strict and cp <= 127:
                result.append(ch)
                self.advance()
            else:
                break
        return ''.join(result)


# ─── Parser ──────────────────────────────────────────────────────────────────

class AddressParser:
    """RFC 5322 compliant email address parser.
    
    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    
    Usage:
        parser = AddressParser(strict=True)
        addr = parser.parse('"John Doe" <john@example.com>')
        print(addr.display_name)  # "John Doe"
        print(addr.local_part)    # "john"
        print(addr.domain)        # "example.com"
    """

    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, reject obs-* productions per §4.1-4.4.
                    If False, accept obsolete forms per §4.4.
        """
        self.strict = strict
        self._lexer: Optional[RFC5322Lexer] = None
        self._current: Optional[Token] = None
        self._all_comments: list[str] = []

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address.
        
        Args:
            raw: Raw email address string (e.g., 'user@example.com' or
                 '"John Doe" <john@example.com>')
        
        Returns:
            RFC5322Address with parsed components.
        
        Raises:
            ValueError: If the input is not a valid RFC 5322 address.
        """
        if not raw or len(raw) > 998:
            raise ValueError(f"Input must be 1-998 characters, got {len(raw)}")
        
        self._lexer = RFC5322Lexer(raw, strict=self.strict)
        self._all_comments = []
        self._advance()
        
        result = self._parse_address()
        
        if self._current.type != TokenType.EOF:
            raise ValueError(f"Unexpected token after address: {self._current}")
        
        result.source = raw
        result.comments = self._all_comments
        return result

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4.
        
        address-list = (address *("," address)) / obs-addr-list
        """
        if not raw:
            return []
        
        self._lexer = RFC5322Lexer(raw, strict=self.strict)
        self._all_comments = []
        self._advance()
        
        results: list[RFC5322Address] = []
        results.append(self._parse_address())
        
        while self._current.type == TokenType.COMMA:
            self._advance()
            results.append(self._parse_address())
        
        if self._current.type != TokenType.EOF:
            raise ValueError(f"Unexpected token at end of address list: {self._current}")
        
        # Attach comments and source
        for r in results:
            r.comments = list(self._all_comments)
            r.source = raw
        
        return results

    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4.
        
        mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list
        """
        results = self.parse_address_list(raw)
        # Validate that all entries are mailboxes, not groups
        for addr in results:
            if addr.is_group:
                raise ValueError(
                    f"Group addresses are not allowed in mailbox-list: {addr.source}")
        return results

    # ── Internal: Recursive Descent Parser ────────────────────────────────

    def _advance(self):
        """Get next token from lexer."""
        if self._lexer is None:
            raise RuntimeError("Lexer not initialized")
        t = self._lexer.next_token()
        if t.comments:
            self._all_comments.extend(t.comments)
        self._current = t

    def _expect(self, ttype: str) -> Token:
        """Require current token to be of type `ttype`, advance."""
        if self._current.type != ttype:
            raise ValueError(f"Expected {ttype}, got {self._current}")
        tok = self._current
        self._advance()
        return tok

    def _parse_address(self) -> RFC5322Address:
        """address = mailbox / group"""
        # Peek ahead: group has display-name ":" ...
        if self._current.type == TokenType.ATOM:
            # Could be a display-name starting a group or name-addr
            # Group: display-name ":" [group-list] ";"
            # Name-addr: [display-name] angle-addr
            # Save state
            saved_pos = self._lexer.pos
            saved_token = self._current
            saved_comments = list(self._all_comments)
            
            display_name = self._parse_phrase()
            
            if self._current.type == TokenType.COLON:
                # This is a group
                return self._finish_group(display_name)
            
            if self._current.type == TokenType.LT:
                # This is a name-addr: [display-name] angle-addr
                return self._finish_name_addr(display_name)
            
            # Could be an addr-spec with display-name that's actually local-part
            # Restore and try addr-spec
            # But first check if it looks like an addr-spec (has "@" or dot-atom)
            if self._current.type == TokenType.AT or self._current.type == TokenType.DOT:
                self._lexer.pos = saved_pos
                self._current = saved_token
                self._all_comments = saved_comments
                return self._parse_addr_spec_wrapper()
            
            # If display_name was followed by angle-addr, parse that
            if self._current.type == TokenType.LT:
                return self._finish_name_addr(display_name)
            
            raise ValueError(f"Unexpected token in address: {self._current}")
        
        if self._current.type == TokenType.LT:
            # angle-addr without display-name: name-addr
            return self._parse_name_addr()
        
        if self._current.type == TokenType.QUOTED_STRING:
            # Could be a display-name or a quoted local-part
            saved_pos = self._lexer.pos
            saved_token = self._current
            saved_comments = list(self._all_comments)
            
            display_name = self._parse_phrase()
            
            if self._current.type == TokenType.COLON:
                return self._finish_group(display_name)
            
            if self._current.type == TokenType.LT:
                return self._finish_name_addr(display_name)
            
            # Quoted string followed by '@' = addr-spec with quoted local-part
            if self._current.type == TokenType.AT:
                self._lexer.pos = saved_pos
                self._current = saved_token
                self._all_comments = saved_comments
                return self._parse_addr_spec_wrapper()
            
            raise ValueError(f"Quoted string not part of valid address: {self._current}")
        
        # addr-spec: local-part "@" domain
        return self._parse_addr_spec_wrapper()

    def _parse_addr_spec_wrapper(self) -> RFC5322Address:
        """Parse addr-spec and return RFC5322Address."""
        local, domain = self._parse_addr_spec()
        return RFC5322Address(
            display_name=None,
            local_part=local,
            domain=domain,
        )

    def _parse_addr_spec(self) -> tuple[str, str]:
        """addr-spec = local-part "@" domain
        
        Returns (local_part, domain).
        """
        local = self._parse_local_part()
        self._expect(TokenType.AT)
        domain = self._parse_domain()
        return local, domain

    def _parse_local_part(self) -> str:
        """local-part = dot-atom / quoted-string / obs-local-part"""
        if self._current.type == TokenType.QUOTED_STRING:
            val = self._current.value
            self._advance()
            return val
        
        if self._current.type == TokenType.ATOM:
            # Could be dot-atom or obs-local-part
            parts: list[str] = [self._current.value]
            self._advance()
            
            while self._current.type == TokenType.DOT:
                self._advance()
                if self._current.type == TokenType.ATOM:
                    parts.append('.')
                    parts.append(self._current.value)
                    self._advance()
                elif self._current.type == TokenType.QUOTED_STRING and not self.strict:
                    # obs-local-part: allows mixing dot-atom and quoted-string
                    parts.append('.')
                    parts.append(f'"{self._current.value}"')
                    self._advance()
                else:
                    raise ValueError(f"Expected atom after dot in local-part, got {self._current}")
            
            result = ''.join(parts)
            self._validate_local_part(result)
            return result
        
        raise ValueError(f"Expected local-part, got {self._current}")

    def _validate_local_part(self, local: str):
        """Validate local-part constraints per RFC 5322 §3.4.1."""
        # Max length
        if len(local) > 64:
            if self.strict:
                raise ValueError(f"local-part exceeds 64 characters: {len(local)}")
        
        # Check for consecutive dots in strict mode
        if self.strict and '..' in local:
            raise ValueError("local-part contains consecutive dots")

    def _parse_domain(self) -> str:
        """domain = dot-atom / domain-literal / obs-domain"""
        if self._current.type == TokenType.LBRACKET:
            val = self._current.value
            self._advance()
            return f"[{val}]"
        
        # obs-domain: may have leading/trailing dots per §4.4
        if self._current.type == TokenType.DOT:
            if self.strict:
                raise ValueError("Domain cannot start with dot in strict mode")
            parts: list[str] = ['.']
            self._advance()
            if self._current.type != TokenType.ATOM:
                raise ValueError(f"Expected atom after dot in domain, got {self._current}")
            parts.append(self._current.value)
            self._advance()
            while self._current.type == TokenType.DOT:
                self._advance()
                if self._current.type == TokenType.ATOM:
                    parts.append('.')
                    parts.append(self._current.value)
                    self._advance()
                else:
                    break
            result = ''.join(parts)
            return result
        
        if self._current.type == TokenType.ATOM:
            parts: list[str] = [self._current.value]
            self._advance()
            
            while self._current.type == TokenType.DOT:
                self._advance()
                if self._current.type == TokenType.ATOM:
                    parts.append('.')
                    parts.append(self._current.value)
                    self._advance()
                else:
                    raise ValueError(f"Expected atom after dot in domain, got {self._current}")
            
            result = ''.join(parts)
            self._validate_domain(result)
            return result
        
        raise ValueError(f"Expected domain, got {self._current}")

    def _validate_domain(self, domain: str):
        """Validate domain constraints."""
        if not domain:
            raise ValueError("Domain cannot be empty")
        if len(domain) > 255:
            if self.strict:
                raise ValueError(f"Domain exceeds 255 characters: {len(domain)}")
        labels = domain.split('.')
        for label in labels:
            if not label:
                if self.strict:
                    raise ValueError("Domain contains empty label")
            elif len(label) > 63 and self.strict:
                raise ValueError(f"Domain label exceeds 63 characters: {label}")

    def _parse_phrase(self) -> str:
        """phrase = 1*word / obs-phrase
        
        word = atom / quoted-string
        
        Returns the display-name text.
        """
        words: list[str] = []
        
        while self._current.type in (TokenType.ATOM, TokenType.QUOTED_STRING):
            if self._current.type == TokenType.ATOM:
                words.append(self._current.value)
            else:
                words.append(self._current.value)
            self._advance()
        
        if not words:
            raise ValueError("Expected display-name (phrase)")
        
        return ' '.join(words)

    def _parse_name_addr(self) -> RFC5322Address:
        """name-addr = [display-name] angle-addr"""
        return self._parse_angle_addr()

    def _parse_angle_addr(self) -> RFC5322Address:
        """angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr"""
        self._expect(TokenType.LT)
        local, domain = self._parse_addr_spec()
        self._expect(TokenType.GT)
        return RFC5322Address(
            local_part=local,
            domain=domain,
        )

    def _finish_name_addr(self, display_name: str) -> RFC5322Address:
        """name-addr = [display-name] angle-addr"""
        self._expect(TokenType.LT)
        local, domain = self._parse_addr_spec()
        self._expect(TokenType.GT)
        return RFC5322Address(
            display_name=display_name,
            local_part=local,
            domain=domain,
        )

    def _finish_group(self, display_name: str) -> RFC5322Address:
        """group = display-name ":" [group-list] ";" [CFWS]
        
        group-list = mailbox-list / CFWS / obs-group-list
        """
        # Consume the colon that the caller already peeked
        self._expect(TokenType.COLON)
        members: list[RFC5322Address] = []
        
        # Parse optional group-list
        if self._current.type != TokenType.SEMICOLON:
            # mailbox-list: mailbox *("," mailbox)
            members.append(self._parse_mailbox())
            while self._current.type == TokenType.COMMA:
                self._advance()
                members.append(self._parse_mailbox())
        
        self._expect(TokenType.SEMICOLON)
        
        return RFC5322Address(
            display_name=display_name,
            is_group=True,
            group_members=members,
        )

    def _parse_mailbox(self) -> RFC5322Address:
        """mailbox = name-addr / addr-spec"""
        if self._current.type == TokenType.LT:
            return self._parse_name_addr()
        
        # Could be display-name + angle-addr or addr-spec
        if self._current.type in (TokenType.ATOM, TokenType.QUOTED_STRING):
            saved_pos = self._lexer.pos
            saved_token = self._current
            saved_comments = list(self._all_comments)
            
            display_name = self._parse_phrase()
            
            if self._current.type == TokenType.LT:
                return self._finish_name_addr(display_name)
            
            # Not angle-addr — restore and parse as addr-spec
            self._lexer.pos = saved_pos
            self._current = saved_token
            self._all_comments = saved_comments
            return self._parse_addr_spec_wrapper()
        
        return self._parse_addr_spec_wrapper()
