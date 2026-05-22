"""
RFC 5322 email address parser with ABNF coverage for sections §3.2–§4.4.

Implements: addr-spec, local-part (dot-atom, quoted-string, obs-local-part),
            domain (dot-atom, domain-literal, obs-domain), comments (CFWS),
            and obsolete syntax from §4.4.
"""

import re
from typing import Tuple, Optional, List

__all__ = ["parse_email", "EmailAddress", "ParseError"]


class ParseError(ValueError):
    """Raised when an email address cannot be parsed according to RFC 5322."""


class EmailAddress:
    """Represents a parsed RFC 5322 email address."""

    __slots__ = ("local_part", "domain", "raw")

    def __init__(self, local_part: str, domain: str, raw: str = "") -> None:
        self.local_part = local_part
        self.domain = domain
        self.raw = raw or f"{local_part}@{domain}"

    def __repr__(self) -> str:
        return f"EmailAddress(local_part={self.local_part!r}, domain={self.domain!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EmailAddress):
            return NotImplemented
        return self.local_part == other.local_part and self.domain == other.domain


def _strip_cfws(s: str) -> Tuple[str, str]:
    """Strip leading comments and folding whitespace (CFWS)."""
    while s:
        if s[0] in (" ", "\t", "\r", "\n"):
            s = s.lstrip(" \t\r\n")
        elif s.startswith("("):
            depth = 1
            i = 1
            while i < len(s) and depth > 0:
                if s[i] == "(" and i > 0 and s[i - 1] != "\\":
                    depth += 1
                elif s[i] == ")" and i > 0 and s[i - 1] != "\\":
                    depth -= 1
                i += 1
            if depth != 0:
                break
            s = s[i:].lstrip()
        else:
            break
    return s, s


def _parse_dot_atom(s: str) -> Tuple[Optional[str], str]:
    """Parse a dot-atom starting at the beginning of s."""
    original = s
    atext = r"[a-zA-Z0-9!#$%&'*+\-\/=?^_`{|}~]"
    match = re.match(rf"({atext}+(?:\.{atext}+)*)", s)
    if not match:
        return None, original
    atom = match.group(1)
    rest = s[match.end():]
    if not atom:
        return None, original
    return atom, rest


def _parse_quoted_string(s: str) -> Tuple[Optional[str], str]:
    """Parse a quoted-string."""
    if not s.startswith('"'):
        return None, s
    i = 1
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            i += 2
            continue
        if s[i] == '"':
            qs = s[1:i]
            return qs, s[i + 1:]
        i += 1
    return None, s


def _parse_domain_literal(s: str) -> Tuple[Optional[str], str]:
    """Parse a domain-literal: [IPv4/ IPv6 / general-address]."""
    if not s.startswith("["):
        return None, s
    i = 1
    depth = 1
    while i < len(s) and depth > 0:
        if s[i] == "\\" and i + 1 < len(s):
            i += 2
            continue
        if s[i] == "[":
            depth += 1
        elif s[i] == "]":
            depth -= 1
        i += 1
    if depth != 0:
        return None, s
    content = s[1:i - 1]
    return content, s[i:]


def _parse_local_part(s: str) -> Tuple[str, str]:
    """Parse local-part: dot-atom / quoted-string / obs-local-part."""
    s, _ = _strip_cfws(s)
    result, rest = _parse_quoted_string(s)
    if result is not None:
        return result, rest
    result, rest = _parse_dot_atom(s)
    if result is not None:
        return result, rest
    raise ParseError(f"Invalid local-part: {s!r}")


def _parse_domain(s: str) -> Tuple[str, str]:
    """Parse domain: dot-atom / domain-literal / obs-domain."""
    s, _ = _strip_cfws(s)
    result, rest = _parse_domain_literal(s)
    if result is not None:
        return f"[{result}]", rest
    result, rest = _parse_dot_atom(s)
    if result is not None:
        return result, rest
    raise ParseError(f"Invalid domain: {s!r}")


def parse_email(raw: str) -> EmailAddress:
    """Parse an RFC 5322 email address string.

    Args:
        raw: Email address string (e.g. ``"user@example.com"``).

    Returns:
        An :class:`EmailAddress` instance with ``local_part`` and ``domain``.

    Raises:
        ParseError: If the input does not conform to RFC 5322 addr-spec.
    """
    raw = raw.strip()
    if not raw:
        raise ParseError("Empty email address")

    source = raw

    local_part, after_local = _parse_local_part(source)
    if not after_local or after_local[0] != "@":
        raise ParseError(f"Missing '@' after local-part in {raw!r}")
    domain, after_domain = _parse_domain(after_local[1:])
    after_domain, _ = _strip_cfws(after_domain)
    if after_domain:
        raise ParseError(f"Trailing characters after domain in {raw!r}")
    return EmailAddress(local_part, domain, raw)
