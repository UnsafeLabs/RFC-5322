"""
RFC 5322 — Internet Message Format Email Address Parser
======================================================

Implements §§3.2–3.4 (lexical tokens, date/time, address specification)
and §4.4 (obsolete syntax) of RFC 5322.

Usage:
    parser = AddressParser(strict=True)
    addr = parser.parse('"John Doe" <john@example.com>')
    addrs = parser.parse_address_list('alice@a.com, bob@b.com')
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ── Character Classes ────────────────────────────────────────────────

def _is_atext(ch: str) -> bool:
    if 'a' <= ch <= 'z' or 'A' <= ch <= 'Z' or '0' <= ch <= '9':
        return True
    return ch in '!#$%&\'*+-/=?^_`{|}~'

def _is_dtext(ch: str) -> bool:
    code = ord(ch)
    return (33 <= code <= 90) or (94 <= code <= 126)

def _is_qtext(ch: str) -> bool:
    code = ord(ch)
    return code == 33 or (35 <= code <= 91) or (93 <= code <= 126)

def _is_ctext(ch: str) -> bool:
    code = ord(ch)
    return (33 <= code <= 39) or (42 <= code <= 91) or (93 <= code <= 126)

def _is_wsp(ch: str) -> bool:
    return ch in (' ', '\t')


# ── Data Model ────────────────────────────────────────────────────────

@dataclass
class RFC5322Address:
    """A parsed RFC 5322 email address."""
    display_name: Optional[str] = None
    local_part: Optional[str] = None
    domain: Optional[str] = None
    is_group: bool = False
    group_members: list['RFC5322Address'] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""

    def __repr__(self) -> str:
        if self.is_group:
            members = ", ".join(str(m) for m in self.group_members)
            return f"{self.display_name}:{members};"
        if self.display_name:
            return f"{self.display_name} <{self.local_part}@{self.domain}>"
        return f"{self.local_part}@{self.domain}"


# ── Tokenizer ────────────────────────────────────────────────────────

class _Tokenizer:
    """Consumes the input string; provides token helpers."""

    def __init__(self, source: str):
        self.src = source
        self.pos = 0
        self.comments: list[str] = []

    def at_end(self) -> bool:
        return self.pos >= len(self.src)

    def peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        return self.src[idx] if 0 <= idx < len(self.src) else None

    def consume(self) -> Optional[str]:
        ch = self.peek()
        if ch is not None:
            self.pos += 1
        return ch

    def skip(self, n: int = 1) -> None:
        self.pos = min(self.pos + n, len(self.src))

    def skip_fws(self) -> None:
        """FWS = ([*WSP CRLF] 1*WSP) / obs-FWS"""
        saved = self.pos
        pos2 = self.pos
        while pos2 < len(self.src) and _is_wsp(self.src[pos2]):
            pos2 += 1
        if pos2 + 1 < len(self.src) and self.src[pos2:pos2+2] == '\r\n':
            pos2 += 2
        ws_count = 0
        while pos2 < len(self.src) and _is_wsp(self.src[pos2]):
            pos2 += 1
            ws_count += 1
        if ws_count > 0:
            self.pos = pos2
            return
        if self.pos < len(self.src) and _is_wsp(self.src[self.pos]):
            self.pos += 1
            while self.pos < len(self.src) and _is_wsp(self.src[self.pos]):
                self.pos += 1
            return
        self.pos = saved

    def skip_comment(self) -> bool:
        """comment = "(" *([FWS] ccontent) [FWS] ")" """
        saved = self.pos
        if self.peek() != '(':
            return False
        self.pos += 1
        depth = 1
        text_parts: list[str] = []
        while depth > 0 and self.pos < len(self.src):
            ch = self.consume()
            if ch is None:
                break
            if ch == '\\' and self.pos < len(self.src):
                text_parts.append(ch)
                text_parts.append(self.consume())
            elif ch == '(':
                depth += 1
                text_parts.append(ch)
            elif ch == ')':
                depth -= 1
                if depth > 0:
                    text_parts.append(ch)
            else:
                text_parts.append(ch)
        if depth == 0:
            content = ''.join(text_parts).strip()
            self.comments.append(content)
            return True
        self.pos = saved
        return False

    def skip_cfws(self) -> None:
        """CFWS = (1*([FWS] comment) [FWS]) / FWS"""
        saved = self.pos
        matched = False
        while True:
            self.skip_fws()
            if not self.skip_comment():
                break
            matched = True
        if matched:
            self.skip_fws()
            return
        self.skip_fws()
        if self.pos != saved:
            return
        self.pos = saved


# ── Address Parser ────────────────────────────────────────────────────

class RFC5322SyntaxError(ValueError):
    pass


class AddressParser:
    """RFC 5322 compliant email address parser.

    Args:
        strict: If True, reject obs-* productions.
                If False, accept obsolete forms per §4.4.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict
        self._tok: _Tokenizer | None = None

    # ── Public API ──────────────────────────────────────────────────

    def parse(self, raw: str) -> RFC5322Address:
        self._tok = _Tokenizer(raw.strip())
        addr = self._address()
        self._tok.skip_cfws()
        if not self._tok.at_end():
            raise RFC5322SyntaxError(
                f"Unexpected trailing content at position {self._tok.pos}"
            )
        addr.source = raw.strip()
        addr.comments = self._tok.comments[:]
        return addr

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        self._tok = _Tokenizer(raw.strip())
        addrs: list[RFC5322Address] = []
        self._tok.skip_cfws()
        if self._tok.at_end():
            return addrs
        addrs.append(self._address())
        self._tok.skip_cfws()
        while not self._tok.at_end():
            if self._tok.peek() == ',':
                self._tok.skip()
                self._tok.skip_cfws()
                if self._tok.at_end():
                    break
                addrs.append(self._address())
                self._tok.skip_cfws()
            else:
                if not self.strict:
                    break
                raise RFC5322SyntaxError(
                    f"Expected ',' or end at position {self._tok.pos}"
                )
        for a in addrs:
            a.source = raw.strip()
            a.comments = self._tok.comments[:]
        return addrs

    # ── Grammar Productions ─────────────────────────────────────────

    def _address(self) -> RFC5322Address:
        saved = self._tok.pos
        saved_n = len(self._tok.comments)
        try:
            return self._group()
        except RFC5322SyntaxError:
            self._tok.pos = saved
            self._tok.comments = self._tok.comments[:saved_n]
        return self._mailbox()

    def _group(self) -> RFC5322Address:
        name = self._phrase()
        self._tok.skip_cfws()
        if self._tok.consume() != ':':
            raise RFC5322SyntaxError("Expected ':' after group display name")
        self._tok.skip_cfws()
        members: list[RFC5322Address] = []
        if self._tok.peek() != ';':
            members = self._group_list()
        self._tok.skip_cfws()
        if self._tok.consume() != ';':
            raise RFC5322SyntaxError("Expected ';' to close group")
        return RFC5322Address(display_name=name, is_group=True, group_members=members)

    def _group_list(self) -> list[RFC5322Address]:
        self._tok.skip_cfws()
        if self._tok.at_end() or self._tok.peek() == ';':
            return []
        return self._mailbox_list()

    def _mailbox_list(self) -> list[RFC5322Address]:
        addrs: list[RFC5322Address] = [self._mailbox()]
        self._tok.skip_cfws()
        while self._tok.peek() == ',':
            self._tok.skip()
            self._tok.skip_cfws()
            if self._tok.at_end():
                break
            addrs.append(self._mailbox())
            self._tok.skip_cfws()
        return addrs

    def _mailbox(self) -> RFC5322Address:
        saved = self._tok.pos
        try:
            return self._name_addr()
        except RFC5322SyntaxError:
            self._tok.pos = saved
        local = self._local_part()
        self._tok.skip_cfws()
        if self._tok.consume() != '@':
            raise RFC5322SyntaxError("Expected '@' in addr-spec")
        self._tok.skip_cfws()
        domain = self._domain()
        return RFC5322Address(local_part=local, domain=domain)

    def _name_addr(self) -> RFC5322Address:
        saved = self._tok.pos
        name: Optional[str] = None
        try:
            name = self._phrase()
        except RFC5322SyntaxError:
            self._tok.pos = saved
            name = None
        local_part, domain, _ = self._angle_addr()
        return RFC5322Address(display_name=name, local_part=local_part, domain=domain)

    def _angle_addr(self) -> tuple[str, str, list[str]]:
        self._tok.skip_cfws()
        if self._tok.consume() != '<':
            raise RFC5322SyntaxError("Expected '<' in angle-addr")
        self._tok.skip_cfws()
        local = self._local_part()
        self._tok.skip_cfws()
        if self._tok.consume() != '@':
            raise RFC5322SyntaxError("Expected '@' in angle-addr")
        self._tok.skip_cfws()
        domain = self._domain()
        self._tok.skip_cfws()
        if self._tok.consume() != '>':
            raise RFC5322SyntaxError("Expected '>' to close angle-addr")
        return local, domain, []

    def _phrase(self) -> str:
        parts: list[str] = []
        while True:
            saved = self._tok.pos
            self._tok.skip_cfws()
            if self._tok.at_end():
                break
            part: Optional[str] = None
            try:
                part = self._quoted_string()
            except RFC5322SyntaxError:
                self._tok.pos = saved
            if part is None:
                try:
                    part = self._atom()
                except RFC5322SyntaxError:
                    self._tok.pos = saved
            if part is None and not self.strict and self._tok.peek() == '.':
                # obs-phrase: dots are allowed between words
                parts[-1] = parts[-1] + '.' if parts else '.'
                self._tok.skip()
                continue
            if part is None:
                break
            parts.append(part)
            # Non-strict: allow trailing dots in obs-phrase
            if not self.strict:
                while self._tok.peek() == '.':
                    parts[-1] += '.'
                    self._tok.skip()
        if not parts:
            raise RFC5322SyntaxError("Expected at least one word in phrase")
        return ' '.join(parts)

    def _atom(self) -> str:
        self._tok.skip_cfws()
        chars: list[str] = []
        while self._tok.pos < len(self._tok.src) and _is_atext(self._tok.peek()):
            chars.append(self._tok.consume())
        if not chars:
            raise RFC5322SyntaxError("Expected atext in atom")
        self._tok.skip_cfws()
        return ''.join(chars)

    def _dot_atom(self) -> str:
        self._tok.skip_cfws()
        chars: list[str] = []
        while self._tok.pos < len(self._tok.src) and _is_atext(self._tok.peek()):
            chars.append(self._tok.consume())
        if not chars:
            raise RFC5322SyntaxError("Expected atext in dot-atom")
        while self._tok.pos < len(self._tok.src) and self._tok.peek() == '.':
            saved = self._tok.pos
            self._tok.skip()
            if self._tok.pos < len(self._tok.src) and _is_atext(self._tok.peek()):
                chars.append('.')
                while self._tok.pos < len(self._tok.src) and _is_atext(self._tok.peek()):
                    chars.append(self._tok.consume())
            else:
                self._tok.pos = saved
                break
        self._tok.skip_cfws()
        return ''.join(chars)

    def _quoted_string(self) -> str:
        self._tok.skip_cfws()
        if self._tok.consume() != '"':
            raise RFC5322SyntaxError("Expected DQUOTE")
        chars: list[str] = []
        while self._tok.pos < len(self._tok.src):
            if self._tok.peek() == '"':
                break
            if self._tok.peek() == '\\':
                self._tok.skip()
                if self._tok.pos < len(self._tok.src):
                    chars.append(self._tok.consume())
                else:
                    raise RFC5322SyntaxError("Unterminated quoted-pair")
            elif self._tok.peek() is not None and _is_qtext(self._tok.peek()):
                chars.append(self._tok.consume())
            elif _is_wsp(self._tok.peek() or ''):
                self._tok.skip_fws()
                if chars and chars[-1] != ' ':
                    chars.append(' ')
            else:
                raise RFC5322SyntaxError(
                    f"Unexpected char {repr(self._tok.peek())} in quoted-string"
                )
        if self._tok.consume() != '"':
            raise RFC5322SyntaxError("Unterminated quoted-string")
        self._tok.skip_cfws()
        return ''.join(chars).strip()

    def _local_part(self) -> str:
        saved = self._tok.pos
        if self._tok.peek() == '"' or (self._tok.peek() is not None and _is_wsp(self._tok.peek())):
            try:
                return self._quoted_string()
            except RFC5322SyntaxError:
                self._tok.pos = saved
        try:
            return self._dot_atom()
        except RFC5322SyntaxError:
            self._tok.pos = saved
        if not self.strict:
            try:
                return self._obs_local_part()
            except RFC5322SyntaxError:
                self._tok.pos = saved
        raise RFC5322SyntaxError("Expected local-part")

    def _domain(self) -> str:
        saved = self._tok.pos
        try:
            return self._domain_literal()
        except RFC5322SyntaxError:
            self._tok.pos = saved
        try:
            return self._dot_atom()
        except RFC5322SyntaxError:
            self._tok.pos = saved
        if not self.strict:
            try:
                return self._obs_domain()
            except RFC5322SyntaxError:
                self._tok.pos = saved
        raise RFC5322SyntaxError("Expected domain")

    def _domain_literal(self) -> str:
        self._tok.skip_cfws()
        if self._tok.consume() != '[':
            raise RFC5322SyntaxError("Expected '[' for domain-literal")
        chars: list[str] = []
        while self._tok.pos < len(self._tok.src):
            self._tok.skip_fws()
            if self._tok.peek() == ']':
                break
            if self._tok.peek() == '\\':
                self._tok.skip()
                if self._tok.pos < len(self._tok.src):
                    chars.append(self._tok.consume())
                else:
                    raise RFC5322SyntaxError("Unterminated quoted-pair in domain-literal")
            elif self._tok.peek() is not None and _is_dtext(self._tok.peek()):
                chars.append(self._tok.consume())
            elif _is_wsp(self._tok.peek() or ''):
                self._tok.skip_fws()
            else:
                break
        self._tok.skip_fws()
        if self._tok.consume() != ']':
            raise RFC5322SyntaxError("Unterminated domain-literal")
        self._tok.skip_cfws()
        return '[' + ''.join(chars) + ']'

    # ── Obsolete Syntax (§4.4) ──────────────────────────────────────

    def _obs_local_part(self) -> str:
        parts: list[str] = []
        while True:
            saved = self._tok.pos
            self._tok.skip_cfws()
            if self._tok.at_end():
                break
            word: Optional[str] = None
            try:
                word = self._quoted_string()
            except RFC5322SyntaxError:
                self._tok.pos = saved
            if word is None:
                try:
                    word = self._atom()
                except RFC5322SyntaxError:
                    self._tok.pos = saved
            if word is None:
                break
            parts.append(word)
            self._tok.skip_cfws()
            if self._tok.peek() == '.':
                self._tok.skip()
            else:
                break
        if not parts:
            raise RFC5322SyntaxError("Expected obs-local-part")
        return '.'.join(parts)

    def _obs_domain(self) -> str:
        parts: list[str] = []
        while True:
            saved = self._tok.pos
            self._tok.skip_cfws()
            if self._tok.at_end():
                break
            try:
                part = self._atom()
                parts.append(part)
            except RFC5322SyntaxError:
                self._tok.pos = saved
                break
            self._tok.skip_cfws()
            if self._tok.peek() == '.':
                self._tok.skip()
            else:
                break
        if not parts:
            raise RFC5322SyntaxError("Expected obs-domain")
        return '.'.join(parts)
