"""RFC 5322 address parser.

The parser implements the address-related ABNF from RFC 5322 sections
3.2 through 3.4, with optional support for the obsolete address forms in
section 4.4. It intentionally keeps the public surface small and has no
dependencies outside the Python standard library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re


ATEXT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~")
NO_WS_CTL = set(chr(i) for i in list(range(1, 9)) + [11, 12] + list(range(14, 32)) + [127])


class ParseError(ValueError):
    """Raised when an address does not match the supported RFC 5322 grammar."""


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""

    display_name: str | None
    local_part: str
    domain: str
    is_group: bool = False
    group_members: list["RFC5322Address"] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""


class AddressParser:
    """RFC 5322 compliant email address parser.

    Args:
        strict: If True, reject obsolete address productions from section 4.4.
            If False, accept obs-angle-addr, obs-local-part, obs-domain,
            obs-mbox-list, obs-addr-list, and obs-group-list.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""

        source = self._validate_input(raw)
        group_colon = self._find_top_level(source, ":")
        if group_colon != -1:
            return self._parse_group(source, group_colon)
        return self._parse_mailbox(source)

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per RFC 5322 section 3.4."""

        source = self._validate_input(raw)
        parts = self._split_top_level(source, ",")
        addresses: list[RFC5322Address] = []
        for part in parts:
            if not part.strip():
                if self.strict:
                    raise ParseError("empty address-list member requires obsolete syntax")
                continue
            addresses.append(self.parse(part))
        if not addresses and self.strict:
            raise ParseError("address-list must contain at least one address")
        return addresses

    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per RFC 5322 section 3.4."""

        mailboxes = self.parse_address_list(raw)
        if any(item.is_group for item in mailboxes):
            raise ParseError("mailbox-list cannot contain group addresses")
        return mailboxes

    def _parse_group(self, source: str, colon: int) -> RFC5322Address:
        semi = self._find_top_level(source, ";")
        if semi == -1 or semi < colon:
            raise ParseError("group address must end with a semicolon")
        trailer = source[semi + 1 :]
        clean_trailer, trailer_comments = self._strip_cfws(trailer)
        if clean_trailer.strip():
            raise ParseError("unexpected text after group semicolon")

        display_raw = source[:colon]
        members_raw = source[colon + 1 : semi]
        display, display_comments = self._parse_phrase(display_raw)
        members: list[RFC5322Address] = []
        member_comments: list[str] = []
        clean_members, clean_member_comments = self._strip_cfws(members_raw)
        member_comments.extend(clean_member_comments)
        if not clean_members.strip():
            pass
        elif members_raw.strip():
            try:
                members = self.parse_mailbox_list(members_raw)
            except ParseError:
                if self.strict:
                    raise
                members = [
                    mailbox
                    for chunk in self._split_top_level(members_raw, ",")
                    if (chunk.strip() and (mailbox := self._parse_mailbox(chunk)))
                ]
        for member in members:
            member_comments.extend(member.comments)

        return RFC5322Address(
            display_name=display,
            local_part="",
            domain="",
            is_group=True,
            group_members=members,
            comments=[*display_comments, *member_comments, *trailer_comments],
            source=source,
        )

    def _parse_mailbox(self, source: str) -> RFC5322Address:
        original_source = source
        work = source.strip()
        lt = self._find_top_level(work, "<")
        gt = self._find_matching_angle(work, lt) if lt != -1 else -1
        if lt != -1:
            if gt == -1:
                raise ParseError("angle address is missing closing '>'")
            trailing, trailing_comments = self._strip_cfws(work[gt + 1 :])
            if trailing.strip():
                raise ParseError("unexpected text after angle address")
            display, display_comments = self._parse_phrase(work[:lt])
            addr_source = work[lt + 1 : gt]
            if self._find_top_level(addr_source, ":") != -1:
                if self.strict:
                    raise ParseError("obsolete route address requires permissive mode")
                addr_source = addr_source.split(":", 1)[1]
            parsed = self._parse_addr_spec(addr_source, original_source)
            parsed.display_name = display or None
            parsed.comments = [*display_comments, *parsed.comments, *trailing_comments]
            return parsed
        return self._parse_addr_spec(work, original_source)

    def _parse_addr_spec(self, raw: str, source: str) -> RFC5322Address:
        cleaned, comments = self._strip_cfws(raw)
        at = self._find_top_level(cleaned, "@")
        if at == -1:
            raise ParseError("addr-spec must contain @")
        if self._find_top_level(cleaned[at + 1 :], "@") != -1:
            raise ParseError("addr-spec contains more than one @")

        local_raw = cleaned[:at].strip()
        domain_raw = cleaned[at + 1 :].strip()
        local = self._parse_local_part(local_raw)
        domain = self._parse_domain(domain_raw)
        return RFC5322Address(
            display_name=None,
            local_part=local,
            domain=domain,
            is_group=False,
            comments=comments,
            source=source,
        )

    def _parse_local_part(self, raw: str) -> str:
        if not raw:
            raise ParseError("local-part cannot be empty")
        if raw.startswith('"'):
            if not self._is_complete_quoted_string(raw):
                if self.strict:
                    raise ParseError("quoted local-part must be a single quoted-string in strict mode")
                return self._parse_obs_word_list(raw, "local-part")
            return self._parse_quoted_string(raw)
        if self._is_dot_atom(raw):
            return raw
        if self.strict:
            raise ParseError("local-part is not dot-atom or quoted-string")
        return self._parse_obs_word_list(raw, "local-part")

    def _parse_domain(self, raw: str) -> str:
        if not raw:
            raise ParseError("domain cannot be empty")
        if raw.startswith("["):
            return self._parse_domain_literal(raw)
        if self._is_dot_atom(raw):
            return raw
        if self.strict:
            raise ParseError("domain is not dot-atom or domain-literal")
        parts = raw.split(".")
        for part in parts:
            if part and not self._is_atom(part):
                raise ParseError("invalid obs-domain atom")
        if not any(parts):
            raise ParseError("obs-domain cannot be only dots")
        return raw

    def _parse_domain_literal(self, raw: str) -> str:
        if not raw.endswith("]"):
            raise ParseError("domain-literal must end with ]")
        inner = raw[1:-1]
        if "[" in inner or "]" in inner:
            raise ParseError("domain-literal cannot contain unescaped brackets")
        content = self._collapse_fws(inner).strip()
        if not content:
            raise ParseError("domain-literal cannot be empty")
        if content.lower().startswith("ipv6:"):
            try:
                ipaddress.IPv6Address(content[5:])
            except ValueError as exc:
                raise ParseError("invalid IPv6 domain-literal") from exc
            return f"[{content}]"
        try:
            ipaddress.IPv4Address(content)
            return f"[{content}]"
        except ValueError:
            pass
        if self.strict:
            raise ParseError("domain-literal must be IPv4 or IPv6 in strict mode")
        index = 0
        while index < len(content):
            char = content[index]
            code = ord(char)
            if char == "\\":
                if index + 1 >= len(content):
                    raise ParseError("dangling quoted-pair in domain-literal")
                index += 2
                continue
            if char in "[]" or code < 33 or code > 126:
                if char not in NO_WS_CTL:
                    raise ParseError("invalid obs-dtext in domain-literal")
            index += 1
        return f"[{content}]"

    def _parse_obs_word_list(self, raw: str, label: str) -> str:
        parts = self._split_top_level(raw, ".")
        if not parts or any(part == "" for part in parts):
            raise ParseError(f"{label} contains an empty word")
        normalized: list[str] = []
        for part in parts:
            item = part.strip()
            if item.startswith('"'):
                if not self._is_complete_quoted_string(item):
                    raise ParseError(f"invalid quoted-string in obsolete {label}")
                normalized.append(f'"{self._escape_quoted(self._parse_quoted_string(item))}"')
            elif self._is_atom(item):
                normalized.append(item)
            else:
                raise ParseError(f"invalid word in obsolete {label}")
        return ".".join(normalized)

    def _parse_phrase(self, raw: str) -> tuple[str | None, list[str]]:
        cleaned, comments = self._strip_cfws(raw)
        cleaned = cleaned.strip()
        if not cleaned:
            return None, comments
        words = self._read_phrase_words(cleaned)
        if not words:
            raise ParseError("display-name must be a phrase")
        return " ".join(words), comments

    def _read_phrase_words(self, raw: str) -> list[str]:
        words: list[str] = []
        index = 0
        while index < len(raw):
            while index < len(raw) and raw[index].isspace():
                index += 1
            if index >= len(raw):
                break
            if raw[index] == '"':
                end = self._quoted_end(raw, index)
                if end == -1:
                    raise ParseError("unterminated quoted-string in phrase")
                words.append(self._parse_quoted_string(raw[index : end + 1]))
                index = end + 1
                continue
            start = index
            while index < len(raw) and raw[index] in ATEXT:
                index += 1
            if start == index:
                if not self.strict and raw[index] == ".":
                    words.append(".")
                    index += 1
                    continue
                raise ParseError("invalid phrase word")
            words.append(raw[start:index])
        return [word for word in words if word != "."]

    def _parse_quoted_string(self, raw: str) -> str:
        if not self._is_complete_quoted_string(raw):
            raise ParseError("invalid quoted-string")
        body = raw[1:-1]
        result: list[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char == "\\":
                if index + 1 >= len(body):
                    raise ParseError("dangling quoted-pair")
                nxt = body[index + 1]
                if not self._is_vchar_or_wsp(nxt):
                    raise ParseError("quoted-pair must escape VCHAR or WSP")
                result.append(nxt)
                index += 2
                continue
            if char == "\r" and body[index : index + 2] == "\r\n":
                next_index = index + 2
                if next_index < len(body) and body[next_index] in " \t":
                    while next_index < len(body) and body[next_index] in " \t":
                        next_index += 1
                    result.append(" ")
                    index = next_index
                    continue
            if char in {'"', "\\"} or ord(char) < 32 or ord(char) == 127:
                raise ParseError("invalid qcontent")
            result.append(char)
            index += 1
        return "".join(result)

    def _strip_cfws(self, raw: str) -> tuple[str, list[str]]:
        unfolded = self._collapse_fws(raw)
        result: list[str] = []
        comments: list[str] = []
        index = 0
        while index < len(unfolded):
            char = unfolded[index]
            if char == '"':
                end = self._quoted_end(unfolded, index)
                if end == -1:
                    raise ParseError("unterminated quoted-string")
                result.append(unfolded[index : end + 1])
                index = end + 1
                continue
            if char == "[":
                end = self._literal_end(unfolded, index)
                if end == -1:
                    raise ParseError("unterminated domain-literal")
                result.append(unfolded[index : end + 1])
                index = end + 1
                continue
            if char == "(":
                comment, index = self._consume_comment(unfolded, index)
                comments.append(comment)
                continue
            result.append(char)
            index += 1

        return self._normalize_outside_quotes("".join(result)).strip(), comments

    def _consume_comment(self, raw: str, start: int) -> tuple[str, int]:
        depth = 1
        index = start + 1
        out: list[str] = []
        while index < len(raw):
            char = raw[index]
            if char == "\\":
                if index + 1 >= len(raw):
                    raise ParseError("dangling quoted-pair in comment")
                nxt = raw[index + 1]
                if not self._is_vchar_or_wsp(nxt):
                    raise ParseError("quoted-pair in comment must escape VCHAR or WSP")
                out.append(nxt)
                index += 2
                continue
            if char == "(":
                depth += 1
                out.append(char)
                index += 1
                continue
            if char == ")":
                depth -= 1
                if depth == 0:
                    return "".join(out).strip(), index + 1
                out.append(char)
                index += 1
                continue
            out.append(char)
            index += 1
        raise ParseError("unterminated comment")

    def _split_top_level(self, raw: str, sep: str) -> list[str]:
        parts: list[str] = []
        start = 0
        index = 0
        quote = False
        bracket = 0
        angle = 0
        comment = 0
        while index < len(raw):
            char = raw[index]
            if quote:
                if char == "\\":
                    index += 2
                    continue
                if char == '"':
                    quote = False
                index += 1
                continue
            if comment:
                if char == "\\":
                    index += 2
                    continue
                if char == "(":
                    comment += 1
                elif char == ")":
                    comment -= 1
                index += 1
                continue
            if char == sep and not bracket and not angle:
                parts.append(raw[start:index].strip())
                start = index + 1
            elif char == '"':
                quote = True
            elif char == "(":
                comment = 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char == "<":
                angle += 1
            elif char == ">" and angle:
                angle -= 1
            index += 1
        parts.append(raw[start:].strip())
        return parts

    def _normalize_outside_quotes(self, raw: str) -> str:
        result: list[str] = []
        index = 0
        quote = False
        bracket = False
        pending_space = False
        delimiters = set("@<>,:;.")
        while index < len(raw):
            char = raw[index]
            if quote:
                result.append(char)
                if char == "\\" and index + 1 < len(raw):
                    index += 1
                    result.append(raw[index])
                elif char == '"':
                    quote = False
                index += 1
                continue
            if bracket:
                result.append(char)
                if char == "\\" and index + 1 < len(raw):
                    index += 1
                    result.append(raw[index])
                elif char == "]":
                    bracket = False
                index += 1
                continue
            if char in " \t":
                pending_space = True
                index += 1
                continue
            if char == '"':
                if pending_space and result and result[-1] not in delimiters:
                    result.append(" ")
                pending_space = False
                quote = True
                result.append(char)
            elif char == "[":
                if pending_space and result and result[-1] not in delimiters:
                    result.append(" ")
                pending_space = False
                bracket = True
                result.append(char)
            elif char in delimiters:
                pending_space = False
                while result and result[-1] == " ":
                    result.pop()
                result.append(char)
            else:
                if pending_space and result and result[-1] not in delimiters:
                    result.append(" ")
                pending_space = False
                result.append(char)
            index += 1
        return "".join(result)

    def _find_top_level(self, raw: str, target: str) -> int:
        index = 0
        quote = False
        bracket = 0
        angle = 0
        comment = 0
        while index < len(raw):
            char = raw[index]
            if quote:
                if char == "\\":
                    index += 2
                    continue
                if char == '"':
                    quote = False
                index += 1
                continue
            if comment:
                if char == "\\":
                    index += 2
                    continue
                if char == "(":
                    comment += 1
                elif char == ")":
                    comment -= 1
                index += 1
                continue
            if char == target and not bracket and not angle:
                return index
            if char == '"':
                quote = True
            elif char == "(":
                comment = 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char == "<":
                angle += 1
            elif char == ">" and angle:
                angle -= 1
            index += 1
        return -1

    def _find_matching_angle(self, raw: str, start: int) -> int:
        if start == -1:
            return -1
        quote = False
        bracket = 0
        comment = 0
        for index in range(start + 1, len(raw)):
            char = raw[index]
            if quote:
                if char == "\\":
                    continue
                if char == '"':
                    quote = False
                continue
            if comment:
                if char == "(":
                    comment += 1
                elif char == ")":
                    comment -= 1
                continue
            if char == '"':
                quote = True
            elif char == "(":
                comment = 1
            elif char == "[":
                bracket += 1
            elif char == "]" and bracket:
                bracket -= 1
            elif char == ">" and not bracket:
                return index
        return -1

    def _quoted_end(self, raw: str, start: int) -> int:
        index = start + 1
        while index < len(raw):
            if raw[index] == "\\":
                index += 2
                continue
            if raw[index] == '"':
                return index
            index += 1
        return -1

    def _literal_end(self, raw: str, start: int) -> int:
        index = start + 1
        while index < len(raw):
            if raw[index] == "\\":
                index += 2
                continue
            if raw[index] == "]":
                return index
            index += 1
        return -1

    def _is_complete_quoted_string(self, raw: str) -> bool:
        return raw.startswith('"') and self._quoted_end(raw, 0) == len(raw) - 1

    def _is_atom(self, raw: str) -> bool:
        return bool(raw) and all(char in ATEXT for char in raw)

    def _is_dot_atom(self, raw: str) -> bool:
        return bool(raw) and all(self._is_atom(part) for part in raw.split("."))

    def _collapse_fws(self, raw: str) -> str:
        return re.sub(r"\r\n[ \t]+", " ", raw)

    def _is_vchar_or_wsp(self, char: str) -> bool:
        code = ord(char)
        return char in " \t" or 33 <= code <= 126

    def _escape_quoted(self, raw: str) -> str:
        return raw.replace("\\", "\\\\").replace('"', '\\"')

    def _validate_input(self, raw: str) -> str:
        if not isinstance(raw, str):
            raise TypeError("raw address must be a string")
        if not raw:
            raise ParseError("address cannot be empty")
        if len(raw) > 998:
            raise ParseError("address exceeds RFC 5322 998 character line limit")
        return raw
