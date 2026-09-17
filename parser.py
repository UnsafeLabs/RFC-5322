from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Iterable


@dataclass(slots=True)
class RFC5322Address:
    display_name: str | None
    local_part: str | None
    domain: str | None
    is_group: bool
    group_members: list[RFC5322Address] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""


class AddressParser:
    def __init__(self, strict: bool = True) -> None:
        self.strict = strict
        self._raw = ""
        self._len = 0
        self._i = 0

    def parse(self, raw: str) -> RFC5322Address:
        self._start(raw)
        value = self._parse_any_address()
        self._skip_cfws(value.comments)
        self._expect_eof()
        value.source = raw
        return value

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        self._start(raw)
        items = self._parse_address_list(kind="address")
        self._skip_cfws(None)
        self._expect_eof()
        return items

    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        self._start(raw)
        items = self._parse_address_list(kind="mailbox")
        self._skip_cfws(None)
        self._expect_eof()
        return items

    def _start(self, raw: str) -> None:
        if not isinstance(raw, str):
            raise TypeError("raw must be a string")
        self._raw = raw
        self._len = len(raw)
        self._i = 0

    def _parse_address_list(self, kind: str) -> list[RFC5322Address]:
        items: list[RFC5322Address] = []
        saw_separator = False
        pending_comments: list[str] = []
        while self._i < self._len:
            self._skip_cfws(pending_comments)
            if self._peek() == ",":
                saw_separator = True
                if self.strict:
                    raise ValueError("empty list member is not allowed in strict mode")
                self._i += 1
                continue
            start = self._i
            if kind == "mailbox":
                item = self._parse_mailbox()
            else:
                item = self._parse_any_address()
            if pending_comments:
                item.comments = pending_comments + item.comments
                pending_comments = []
            item.source = self._raw[start:self._i]
            items.append(item)
            if self._i < self._len and self._peek() == ",":
                saw_separator = True
                self._i += 1
                continue
            break

        if not items and not saw_separator:
            # An entirely empty or CFWS-only input is treated as an empty list
            # only in permissive mode.
            if self.strict:
                raise ValueError("expected at least one list member")
        return items

    def _parse_any_address(self) -> RFC5322Address:
        pos = self._classify_structure()
        if pos == "group":
            return self._parse_group()
        if pos == "name-addr":
            return self._parse_name_addr()
        if pos == "addr-spec":
            return self._parse_addr_spec()
        raise ValueError("expected address or group")

    def _parse_mailbox(self) -> RFC5322Address:
        pos = self._classify_structure()
        if pos == "group":
            raise ValueError("group is not allowed in mailbox list")
        if pos == "name-addr":
            return self._parse_name_addr()
        if pos == "addr-spec":
            return self._parse_addr_spec()
        raise ValueError("expected mailbox")

    def _parse_group(self) -> RFC5322Address:
        comments: list[str] = []
        start = self._i
        display_name = self._parse_phrase(stop_chars={":"}, comments=comments)
        self._skip_cfws(comments)
        self._expect(":")
        self._i += 1
        self._skip_cfws(comments)
        members: list[RFC5322Address] = []
        if self._i < self._len and self._peek() != ";":
            members = self._parse_group_list()
        self._skip_cfws(comments)
        self._expect(";")
        self._i += 1
        comments_after = comments
        self._skip_cfws(comments_after)
        return RFC5322Address(
            display_name=display_name,
            local_part=None,
            domain=None,
            is_group=True,
            group_members=members,
            comments=comments_after,
            source=self._raw[start:self._i],
        )

    def _parse_group_list(self) -> list[RFC5322Address]:
        items: list[RFC5322Address] = []
        pending_comments: list[str] = []
        while self._i < self._len and self._peek() != ";":
            self._skip_cfws(pending_comments)
            if self._i < self._len and self._peek() == ";":
                break
            if self._peek() == ",":
                if self.strict:
                    raise ValueError("empty group-list member is not allowed in strict mode")
                self._i += 1
                continue
            start = self._i
            item = self._parse_mailbox()
            if pending_comments:
                item.comments = pending_comments + item.comments
                pending_comments = []
            item.source = self._raw[start:self._i]
            items.append(item)
            if self._i < self._len and self._peek() == ",":
                self._i += 1
                continue
            break
        return items

    def _parse_name_addr(self) -> RFC5322Address:
        comments: list[str] = []
        start = self._i
        display_name: str | None = None
        self._skip_cfws(comments)
        if self._peek() != "<":
            display_name = self._parse_phrase(stop_chars={"<"}, comments=comments)
            self._skip_cfws(comments)
        self._expect("<")
        self._i += 1
        self._skip_cfws(comments)
        if not self.strict and self._peek() == "@":
            self._parse_obs_route(comments)
        local_part, domain = self._parse_addr_spec_body(comments)
        self._skip_cfws(comments)
        self._expect(">")
        self._i += 1
        self._skip_cfws(comments)
        return RFC5322Address(
            display_name=display_name,
            local_part=local_part,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=comments,
            source=self._raw[start:self._i],
        )

    def _parse_addr_spec(self) -> RFC5322Address:
        comments: list[str] = []
        start = self._i
        local_part, domain = self._parse_addr_spec_body(comments)
        self._skip_cfws(comments)
        return RFC5322Address(
            display_name=None,
            local_part=local_part,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=comments,
            source=self._raw[start:self._i],
        )

    def _parse_addr_spec_body(self, comments: list[str]) -> tuple[str, str]:
        local_part = self._parse_local_part(comments)
        self._skip_cfws(comments)
        self._expect("@")
        self._i += 1
        self._skip_cfws(comments)
        domain = self._parse_domain(comments)
        return local_part, domain

    def _parse_local_part(self, comments: list[str]) -> str:
        if self._peek() == '"':
            return self._parse_quoted_string(comments)
        save = self._i
        try:
            return self._parse_dot_atom(comments)
        except ValueError:
            self._i = save
            if self.strict:
                raise
            return self._parse_obs_local_part(comments)

    def _parse_domain(self, comments: list[str]) -> str:
        if self._peek() == "[":
            return self._parse_domain_literal(comments)
        save = self._i
        try:
            return self._parse_dot_atom(comments)
        except ValueError:
            self._i = save
            if self.strict:
                raise
            return self._parse_obs_domain(comments)

    def _parse_dot_atom(self, comments: list[str]) -> str:
        self._skip_cfws(comments)
        parts = [self._parse_atom_text_with_cfws(comments)]
        while self._i < self._len and self._peek() == ".":
            self._i += 1
            if self._i >= self._len or not self._is_atext_start(self._peek()):
                raise ValueError("expected atext after dot")
            parts.append(self._parse_atom_text_with_cfws(comments))
        self._skip_cfws(comments)
        return ".".join(parts)

    def _parse_obs_local_part(self, comments: list[str]) -> str:
        parts = [self._parse_word_in_obs(comments)]
        while True:
            checkpoint = self._i
            self._skip_cfws(None)
            if self._i >= self._len or self._peek() != ".":
                self._i = checkpoint
                break
            self._i += 1
            self._skip_cfws(None)
            parts.append(self._parse_word_in_obs(comments))
        return ".".join(parts)

    def _parse_obs_domain(self, comments: list[str]) -> str:
        parts = [self._parse_atom_text_with_cfws(comments)]
        while True:
            checkpoint = self._i
            self._skip_cfws(None)
            if self._i >= self._len or self._peek() != ".":
                self._i = checkpoint
                break
            self._i += 1
            self._skip_cfws(None)
            parts.append(self._parse_atom_text_with_cfws(comments))
        return ".".join(parts)

    def _parse_word_in_obs(self, comments: list[str]) -> str:
        if self._peek() == '"':
            return self._parse_quoted_string(comments)
        return self._parse_atom_text_with_cfws(comments)

    def _parse_atom_text(self) -> str:
        self._skip_cfws(None)
        start = self._i
        while self._i < self._len and self._is_atext(self._peek()):
            self._i += 1
        if self._i == start:
            raise ValueError("expected atom")
        value = self._raw[start:self._i]
        self._skip_cfws(None)
        return value

    def _parse_atom_text_with_cfws(self, comments: list[str]) -> str:
        self._skip_cfws(comments)
        start = self._i
        while self._i < self._len and self._is_atext(self._peek()):
            self._i += 1
        if self._i == start:
            raise ValueError("expected atom")
        value = self._raw[start:self._i]
        self._skip_cfws(comments)
        return value

    def _parse_phrase(self, stop_chars: set[str], comments: list[str]) -> str:
        parts: list[str] = []
        while True:
            self._skip_cfws(comments)
            ch = self._peek()
            if ch in stop_chars:
                break
            if ch == '"':
                parts.append(self._parse_quoted_string(comments))
                continue
            if self._is_atext_start(ch):
                parts.append(self._parse_atom_text_with_cfws(comments))
                continue
            if not self.strict and ch == "." and parts:
                self._i += 1
                parts[-1] += "."
                continue
            if parts:
                break
            raise ValueError("expected phrase")
        if not parts:
            raise ValueError("expected phrase")
        return " ".join(parts).strip()

    def _parse_quoted_string(self, comments: list[str]) -> str:
        self._skip_cfws(comments)
        self._expect('"')
        self._i += 1
        parts: list[str] = []
        while self._i < self._len:
            if self._peek() == '"':
                self._i += 1
                self._skip_cfws(comments)
                return "".join(parts)
            if self._starts_fws():
                self._consume_fws()
                parts.append(" ")
                continue
            ch = self._peek()
            if ch == "\\":
                parts.append(self._parse_quoted_pair())
                continue
            if self._is_qtext(ch):
                parts.append(ch)
                self._i += 1
                continue
            raise ValueError("invalid quoted-string content")
        raise ValueError("unterminated quoted-string")

    def _parse_domain_literal(self, comments: list[str]) -> str:
        self._skip_cfws(comments)
        self._expect("[")
        self._i += 1
        parts: list[str] = []
        while self._i < self._len:
            if self._peek() == "]":
                self._i += 1
                self._skip_cfws(comments)
                value = "".join(parts)
                self._validate_domain_literal(value)
                return value
            if self._starts_fws():
                self._consume_fws()
                parts.append(" ")
                continue
            if self._peek() == "\\":
                if self.strict:
                    raise ValueError("quoted-pair is not permitted in domain-literal in strict mode")
                parts.append(self._parse_quoted_pair())
                continue
            ch = self._peek()
            if self._is_dtext(ch):
                parts.append(ch)
                self._i += 1
                continue
            if not self.strict and self._is_obs_dtext(ch):
                parts.append(ch)
                self._i += 1
                continue
            raise ValueError("invalid domain-literal content")
        raise ValueError("unterminated domain-literal")

    def _parse_quoted_pair(self) -> str:
        self._expect("\\")
        self._i += 1
        if self._i >= self._len:
            raise ValueError("unterminated quoted-pair")
        ch = self._peek()
        if self.strict:
            if not (self._is_vchar(ch) or ch in {" ", "\t"}):
                raise ValueError("invalid quoted-pair")
        self._i += 1
        return ch

    def _parse_obs_route(self, comments: list[str]) -> None:
        if self.strict:
            raise ValueError("obsolete route is not permitted in strict mode")
        while self._i < self._len and self._peek() != ":":
            self._skip_cfws(comments)
            if self._peek() == ",":
                self._i += 1
                continue
            if self._peek() != "@":
                raise ValueError("invalid obsolete route")
            self._i += 1
            self._skip_cfws(comments)
            self._parse_obs_domain(comments)
            self._skip_cfws(comments)
            if self._peek() == ",":
                self._i += 1
                continue
            if self._peek() != ":":
                raise ValueError("invalid obsolete route")
        self._expect(":")
        self._i += 1
        self._skip_cfws(comments)

    def _skip_cfws(self, comments: list[str] | None) -> bool:
        consumed = False
        while True:
            progressed = False
            while self._i < self._len and self._peek() in {" ", "\t"}:
                self._i += 1
                consumed = progressed = True
            if self._starts_fws():
                self._consume_fws()
                consumed = progressed = True
            if self._i < self._len and self._peek() == "(":
                if comments is not None:
                    comments.append(self._parse_comment())
                else:
                    self._parse_comment()
                consumed = progressed = True
                continue
            if not progressed:
                return consumed

    def _parse_comment(self) -> str:
        self._expect("(")
        self._i += 1
        parts: list[str] = []
        while self._i < self._len:
            if self._peek() == ")":
                self._i += 1
                return "".join(parts).strip()
            if self._starts_fws():
                self._consume_fws()
                parts.append(" ")
                continue
            if self._peek() == "(":
                nested = self._parse_comment()
                if nested:
                    parts.append(nested)
                continue
            if self._peek() == "\\":
                parts.append(self._parse_quoted_pair())
                continue
            ch = self._peek()
            if self._is_ctext(ch):
                parts.append(ch)
                self._i += 1
                continue
            if not self.strict and self._is_obs_ctext(ch):
                parts.append(ch)
                self._i += 1
                continue
            raise ValueError("invalid comment content")
        raise ValueError("unterminated comment")

    def _consume_fws(self) -> None:
        seen_wsp = False
        while self._i < self._len and self._peek() in {" ", "\t"}:
            self._i += 1
            seen_wsp = True
        if self._i + 1 < self._len and self._raw[self._i] == "\r" and self._raw[self._i + 1] == "\n":
            self._i += 2
            while self._i < self._len and self._peek() in {" ", "\t"}:
                self._i += 1
            seen_wsp = True
            while not self.strict and self._starts_fws():
                self._consume_fws()
                seen_wsp = True
        if not seen_wsp:
            raise ValueError("expected FWS")

    def _starts_fws(self) -> bool:
        if self._i >= self._len:
            return False
        if self._peek() in {" ", "\t"}:
            return True
        return self._i + 1 < self._len and self._raw[self._i] == "\r" and self._raw[self._i + 1] == "\n" and (
            self._i + 2 < self._len and self._raw[self._i + 2] in {" ", "\t"}
        )

    def _classify_structure(self) -> str:
        marks = {"<": None, ":": None, "@": None}
        for ch, idx in self._scan_top_level():
            if ch in marks and marks[ch] is None:
                marks[ch] = idx
        lt = marks["<"]
        colon = marks[":"]
        at = marks["@"]
        if colon is not None and (lt is None or colon < lt) and (at is None or colon < at):
            return "group"
        if lt is not None and (at is None or lt < at):
            return "name-addr"
        if at is not None:
            return "addr-spec"
        return "unknown"

    def _find_top_level(self, target: str) -> int | None:
        for ch, idx in self._scan_top_level():
            if ch == target:
                return idx
        return None

    def _scan_top_level(self) -> Iterable[tuple[str, int]]:
        i = self._i
        depth = 0
        in_quote = False
        in_bracket = False
        while i < self._len:
            ch = self._raw[i]
            if in_quote:
                if ch == "\\" and i + 1 < self._len:
                    i += 2
                    continue
                if ch == '"':
                    in_quote = False
                i += 1
                continue
            if depth > 0:
                if ch == "\\" and i + 1 < self._len:
                    i += 2
                    continue
                if ch == "(":
                    depth += 1
                    i += 1
                    continue
                if ch == ")":
                    depth -= 1
                    i += 1
                    continue
                i += 1
                continue
            if in_bracket:
                if ch == "\\" and i + 1 < self._len:
                    i += 2
                    continue
                if ch == "]":
                    in_bracket = False
                i += 1
                continue
            if ch == '"':
                in_quote = True
                i += 1
                continue
            if ch == "(":
                depth = 1
                i += 1
                continue
            if ch == "[":
                in_bracket = True
                i += 1
                continue
            yield ch, i
            i += 1

    def _validate_domain_literal(self, value: str) -> None:
        if not value:
            return
        candidate = value
        if candidate.lower().startswith("ipv6:"):
            try:
                ipaddress.IPv6Address(candidate[5:])
            except ValueError:
                return
            return
        try:
            ipaddress.IPv4Address(candidate)
        except ValueError:
            return

    def _expect(self, ch: str) -> None:
        if self._i >= self._len or self._raw[self._i] != ch:
            raise ValueError(f"expected {ch!r}")

    def _expect_eof(self) -> None:
        if self._i != self._len:
            raise ValueError("unexpected trailing content")

    def _peek(self, offset: int = 0) -> str:
        idx = self._i + offset
        if idx >= self._len:
            return ""
        return self._raw[idx]

    def _is_atext_start(self, ch: str) -> bool:
        return bool(ch) and self._is_atext(ch)

    def _is_atext(self, ch: str) -> bool:
        return ch.isalnum() or ch in "!#$%&'*+-/=?^_`{|}~"

    def _is_qtext(self, ch: str) -> bool:
        if not ch:
            return False
        code = ord(ch)
        if ch in {'"', "\\"} or ch in {"\r", "\n"}:
            return False
        return 33 <= code <= 126

    def _is_dtext(self, ch: str) -> bool:
        if not ch:
            return False
        code = ord(ch)
        if ch in {"[", "]", "\\"} or ch in {"\r", "\n"}:
            return False
        return 33 <= code <= 90 or 94 <= code <= 126

    def _is_ctext(self, ch: str) -> bool:
        if not ch:
            return False
        code = ord(ch)
        if ch in {"(", ")", "\\"} or ch in {"\r", "\n"}:
            return False
        return 33 <= code <= 39 or 42 <= code <= 91 or 93 <= code <= 126

    def _is_obs_ctext(self, ch: str) -> bool:
        if not ch:
            return False
        code = ord(ch)
        return code in range(1, 9) or code in {11, 12, 127} or 14 <= code <= 31

    def _is_obs_dtext(self, ch: str) -> bool:
        return self._is_obs_ctext(ch)

    def _is_vchar(self, ch: str) -> bool:
        return bool(ch) and 33 <= ord(ch) <= 126
