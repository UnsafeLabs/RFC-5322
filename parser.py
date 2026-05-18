"""RFC 5322 address parser.

The parser implements the address-oriented ABNF from RFC 5322 sections
3.2 through 3.4.1 and enables the obsolete addressing forms from section
4.4 when ``strict=False``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from ipaddress import AddressValueError
from typing import Callable


class RFC5322ParseError(ValueError):
    """Raised when an address does not match the supported RFC 5322 grammar."""


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""

    display_name: str | None
    local_part: str
    domain: str
    is_group: bool
    group_members: list["RFC5322Address"] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""


ATEXT = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-/=?^_`{|}~")
SPECIALS = set('()<>[]:;@\\,."')
WSP = " \t"


class _Cursor:
    def __init__(self, text: str, strict: bool):
        if len(text) > 998:
            raise RFC5322ParseError("address exceeds RFC 5322 line length limit")
        self.text = text
        self.strict = strict
        self.pos = 0
        self.comments: list[str] = []

    def eof(self) -> bool:
        return self.pos >= len(self.text)

    def peek(self) -> str:
        return "" if self.eof() else self.text[self.pos]

    def consume(self, char: str) -> None:
        if self.peek() != char:
            raise RFC5322ParseError(f"expected {char!r} at offset {self.pos}")
        self.pos += 1

    def match(self, char: str) -> bool:
        if self.peek() == char:
            self.pos += 1
            return True
        return False

    def snapshot(self) -> tuple[int, int]:
        return self.pos, len(self.comments)

    def restore(self, snap: tuple[int, int]) -> None:
        self.pos, comments_len = snap
        del self.comments[comments_len:]

    def skip_cfws(self) -> bool:
        consumed = False
        while not self.eof():
            if self._skip_fws():
                consumed = True
                continue
            if self.peek() == "(":
                self.comments.append(self._comment())
                consumed = True
                continue
            break
        return consumed

    def _skip_fws(self) -> bool:
        start = self.pos
        saw = False
        while self.peek() in WSP:
            self.pos += 1
            saw = True
        if self.text.startswith("\r\n", self.pos):
            after = self.pos + 2
            count = 0
            while after + count < len(self.text) and self.text[after + count] in WSP:
                count += 1
            if count:
                self.pos = after + count
                return True
            if self.strict:
                self.pos = start
                return saw
        return saw

    def _quoted_pair(self) -> str:
        self.consume("\\")
        if self.eof():
            raise RFC5322ParseError("unterminated quoted-pair")
        char = self.peek()
        if self.strict and (char not in WSP and not (33 <= ord(char) <= 126)):
            raise RFC5322ParseError("invalid quoted-pair")
        self.pos += 1
        return char

    def _comment(self) -> str:
        self.consume("(")
        out: list[str] = []
        while not self.eof():
            if self._skip_fws():
                out.append(" ")
                continue
            char = self.peek()
            if char == ")":
                self.pos += 1
                return "".join(out)
            if char == "(":
                out.append(self._comment())
                continue
            if char == "\\":
                out.append(self._quoted_pair())
                continue
            code = ord(char)
            if char in "()\\" or code == 127 or (code < 32 and char not in WSP):
                if self.strict:
                    raise RFC5322ParseError("invalid comment character")
            out.append(char)
            self.pos += 1
        raise RFC5322ParseError("unterminated comment")


class AddressParser:
    """RFC 5322 compliant email address parser."""

    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, reject obs-* productions. If False, accept
                obsolete forms per RFC 5322 section 4.4.
        """

        self.strict = strict

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""

        cursor = _Cursor(raw, self.strict)
        address = self._address(cursor, raw)
        cursor.skip_cfws()
        if not cursor.eof():
            raise RFC5322ParseError(f"unexpected trailing input at offset {cursor.pos}")
        self._attach_comments(address, cursor.comments)
        return address

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per RFC 5322 section 3.4."""

        return self._parse_list(raw, self._address, allow_groups=True)

    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per RFC 5322 section 3.4."""

        return self._parse_list(raw, self._mailbox, allow_groups=False)

    def _parse_list(
        self,
        raw: str,
        parser: Callable[[_Cursor, str], RFC5322Address],
        allow_groups: bool,
    ) -> list[RFC5322Address]:
        cursor = _Cursor(raw, self.strict)
        out: list[RFC5322Address] = []
        if cursor.eof():
            raise RFC5322ParseError("empty address list")
        while True:
            source_start = cursor.pos
            comments_start = len(cursor.comments)
            cursor.skip_cfws()
            if not self.strict and cursor.match(","):
                continue
            start = cursor.pos
            item = parser(cursor, raw[start:]) if allow_groups else parser(cursor, raw[start:])
            item.source = raw[source_start:cursor.pos].strip()
            self._attach_comments(item, cursor.comments[comments_start:])
            out.append(item)
            cursor.skip_cfws()
            if cursor.eof():
                return out
            if cursor.match(","):
                snap = cursor.snapshot()
                cursor.skip_cfws()
                at_end = cursor.eof()
                cursor.restore(snap)
                if at_end and not self.strict:
                    return out
                if at_end and self.strict:
                    raise RFC5322ParseError("trailing comma in address list")
                continue
            raise RFC5322ParseError(f"expected comma at offset {cursor.pos}")

    def _address(self, cursor: _Cursor, source: str) -> RFC5322Address:
        snap = cursor.snapshot()
        try:
            return self._group(cursor, source)
        except RFC5322ParseError:
            cursor.restore(snap)
            return self._mailbox(cursor, source)

    def _mailbox(self, cursor: _Cursor, source: str) -> RFC5322Address:
        snap = cursor.snapshot()
        try:
            return self._name_addr(cursor, source)
        except RFC5322ParseError:
            cursor.restore(snap)
            local, domain = self._addr_spec(cursor)
            return RFC5322Address(None, local, domain, False, source=source)

    def _name_addr(self, cursor: _Cursor, source: str) -> RFC5322Address:
        start_comments = len(cursor.comments)
        display_name: str | None = None
        snap = cursor.snapshot()
        try:
            display_name = self._phrase(cursor)
        except RFC5322ParseError:
            cursor.restore(snap)
        cursor.skip_cfws()
        route = False
        if cursor.match("<"):
            if not self.strict:
                route = self._obs_route(cursor)
            local, domain = self._addr_spec(cursor)
            cursor.consume(">")
        else:
            raise RFC5322ParseError("expected angle address")
        cursor.skip_cfws()
        address = RFC5322Address(display_name, local, domain, False, source=source)
        address.comments = cursor.comments[start_comments:]
        if route:
            address.comments.append("obsolete route ignored")
        return address

    def _group(self, cursor: _Cursor, source: str) -> RFC5322Address:
        display_name = self._phrase(cursor)
        cursor.skip_cfws()
        cursor.consume(":")
        members: list[RFC5322Address] = []
        snap = cursor.snapshot()
        cursor.skip_cfws()
        empty_group = cursor.peek() == ";"
        cursor.restore(snap)
        if not empty_group:
            while True:
                member_source_start = cursor.pos
                member_comments_start = len(cursor.comments)
                cursor.skip_cfws()
                if not self.strict and cursor.match(","):
                    continue
                if cursor.peek() == ";":
                    break
                member = self._mailbox(cursor, source)
                member.source = source[member_source_start:cursor.pos].strip()
                self._attach_comments(member, cursor.comments[member_comments_start:])
                members.append(member)
                cursor.skip_cfws()
                if cursor.match(","):
                    cursor.skip_cfws()
                    if cursor.peek() == ";" and self.strict:
                        raise RFC5322ParseError("trailing comma in group")
                    continue
                break
        if not members and self.strict:
            # RFC 5322 allows CFWS-only group-list; empty group is therefore valid.
            pass
        cursor.consume(";")
        cursor.skip_cfws()
        return RFC5322Address(display_name, "", "", True, members, source=source)

    def _addr_spec(self, cursor: _Cursor) -> tuple[str, str]:
        local = self._local_part(cursor)
        cursor.skip_cfws()
        cursor.consume("@")
        domain = self._domain(cursor)
        return local, domain

    def _local_part(self, cursor: _Cursor) -> str:
        snap = cursor.snapshot()
        for parser in (self._dot_atom, self._quoted_string):
            try:
                return parser(cursor)
            except RFC5322ParseError:
                cursor.restore(snap)
        if not self.strict:
            return self._obs_local_part(cursor)
        raise RFC5322ParseError("invalid local-part")

    def _domain(self, cursor: _Cursor) -> str:
        snap = cursor.snapshot()
        for parser in (self._dot_atom, self._domain_literal):
            try:
                return parser(cursor)
            except RFC5322ParseError:
                cursor.restore(snap)
        if not self.strict:
            return self._obs_domain(cursor)
        raise RFC5322ParseError("invalid domain")

    def _phrase(self, cursor: _Cursor) -> str:
        words: list[str] = []
        cursor.skip_cfws()
        while True:
            snap = cursor.snapshot()
            try:
                word = self._word(cursor)
                words.append(word)
                cursor.skip_cfws()
            except RFC5322ParseError:
                cursor.restore(snap)
                if not self.strict and cursor.match("."):
                    words.append(".")
                    cursor.skip_cfws()
                    continue
                break
        if not words:
            raise RFC5322ParseError("expected phrase")
        return " ".join(part for part in words if part != ".").strip()

    def _word(self, cursor: _Cursor) -> str:
        snap = cursor.snapshot()
        try:
            return self._atom(cursor)
        except RFC5322ParseError:
            cursor.restore(snap)
            return self._quoted_string(cursor)

    def _atom(self, cursor: _Cursor) -> str:
        cursor.skip_cfws()
        start = cursor.pos
        while cursor.peek() in ATEXT:
            cursor.pos += 1
        if cursor.pos == start:
            raise RFC5322ParseError("expected atom")
        value = cursor.text[start:cursor.pos]
        cursor.skip_cfws()
        return value

    def _dot_atom(self, cursor: _Cursor) -> str:
        cursor.skip_cfws()
        start = cursor.pos
        parts = [self._atext_run(cursor)]
        while cursor.match("."):
            parts.append(self._atext_run(cursor))
        value = ".".join(parts)
        if cursor.pos == start:
            raise RFC5322ParseError("expected dot-atom")
        cursor.skip_cfws()
        return value

    def _atext_run(self, cursor: _Cursor) -> str:
        start = cursor.pos
        while cursor.peek() in ATEXT:
            cursor.pos += 1
        if cursor.pos == start:
            raise RFC5322ParseError("expected atext")
        return cursor.text[start:cursor.pos]

    def _quoted_string(self, cursor: _Cursor) -> str:
        cursor.skip_cfws()
        cursor.consume('"')
        out: list[str] = []
        while not cursor.eof():
            if cursor._skip_fws():
                out.append(" ")
                continue
            char = cursor.peek()
            if char == '"':
                cursor.pos += 1
                cursor.skip_cfws()
                return "".join(out)
            if char == "\\":
                out.append(cursor._quoted_pair())
                continue
            code = ord(char)
            valid_qtext = char == "!" or char in "#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
            if not valid_qtext:
                if self.strict or char in "\r\n":
                    raise RFC5322ParseError("invalid quoted-string character")
            out.append(char)
            cursor.pos += 1
        raise RFC5322ParseError("unterminated quoted-string")

    def _domain_literal(self, cursor: _Cursor) -> str:
        cursor.skip_cfws()
        cursor.consume("[")
        out: list[str] = []
        while not cursor.eof():
            if cursor._skip_fws():
                out.append(" ")
                continue
            char = cursor.peek()
            if char == "]":
                cursor.pos += 1
                cursor.skip_cfws()
                value = "".join(out).strip()
                self._validate_address_literal(value)
                return f"[{value}]"
            if char == "\\" and not self.strict:
                out.append(cursor._quoted_pair())
                continue
            code = ord(char)
            if char in "[]\\" or code == 127 or code < 33:
                raise RFC5322ParseError("invalid domain-literal character")
            out.append(char)
            cursor.pos += 1
        raise RFC5322ParseError("unterminated domain-literal")

    def _validate_address_literal(self, value: str) -> None:
        if not value:
            raise RFC5322ParseError("empty domain-literal")
        try:
            if value.lower().startswith("ipv6:"):
                ipaddress.IPv6Address(value[5:])
                return
            if all(part.isdigit() for part in value.split(".")) and value.count(".") == 3:
                ipaddress.IPv4Address(value)
        except AddressValueError as exc:
            raise RFC5322ParseError(str(exc)) from exc

    def _obs_local_part(self, cursor: _Cursor) -> str:
        words = [self._word(cursor)]
        while cursor.match("."):
            words.append(self._word(cursor))
        return ".".join(words)

    def _obs_domain(self, cursor: _Cursor) -> str:
        cursor.skip_cfws()
        parts: list[str] = []
        if cursor.match("."):
            parts.append("")
        parts.append(self._atom(cursor))
        while cursor.match("."):
            snap = cursor.snapshot()
            try:
                parts.append(self._atom(cursor))
            except RFC5322ParseError:
                cursor.restore(snap)
                parts.append("")
                break
        return ".".join(parts)

    def _obs_route(self, cursor: _Cursor) -> bool:
        snap = cursor.snapshot()
        saw_route = False
        try:
            while True:
                cursor.skip_cfws()
                if not cursor.match("@"):
                    break
                self._domain(cursor)
                saw_route = True
                cursor.skip_cfws()
                cursor.match(",")
            if saw_route:
                cursor.consume(":")
                return True
        except RFC5322ParseError:
            cursor.restore(snap)
            return False
        cursor.restore(snap)
        return False

    def _attach_comments(self, address: RFC5322Address, comments: list[str]) -> None:
        seen = list(address.comments)
        for comment in comments:
            if comment not in seen:
                seen.append(comment)
        address.comments = seen
