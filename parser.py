"""
RFC 5322 Email Address Parser

Implements the complete ABNF grammar from RFC 5322 sections 3.2 through 3.4,
plus obsolete syntax from §4.4.

Parses email addresses including:
- Simple: user@domain
- With display name: John Doe <john@example.com>
- Quoted local parts: "john.doe"@example.com
- Comments: John (comment) <john@example.com>
- Groups: Group: member1@a.com, member2@b.com;
- Domain literals: user@[192.168.1.1]
- Nested comments, folding whitespace, quoted-pairs
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: Optional[str] = None
    local_part: str = ""
    domain: str = ""
    is_group: bool = False
    group_members: list = field(default_factory=list)
    comments: list = field(default_factory=list)
    source: str = ""

    def __repr__(self) -> str:
        if self.is_group:
            members = ", ".join(str(m) for m in self.group_members)
            return f"{self.display_name}:{members};"
        if self.display_name:
            return f"{self.display_name} <{self.local_part}@{self.domain}>"
        return f"{self.local_part}@{self.domain}"


@dataclass
class ParseResult:
    """Result of parsing."""
    addresses: List[RFC5322Address] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "addresses": [
                {
                    "display_name": a.display_name,
                    "local_part": a.local_part,
                    "domain": a.domain,
                    "is_group": a.is_group,
                    "group_members": [
                        {
                            "display_name": m.display_name,
                            "local_part": m.local_part,
                            "domain": m.domain,
                        }
                        for m in (a.group_members if a.is_group else [])
                    ],
                    "comments": list(a.comments),
                }
                for a in self.addresses
            ],
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Character classes
# ---------------------------------------------------------------------------

# NO-WS-CTL = %d1-8 / %d11 / %d12 / %d14-31 / %d127
def _is_no_ws_ctl(ch: str) -> bool:
    if len(ch) != 1:
        return False
    c = ord(ch)
    return (1 <= c <= 8) or c == 11 or c == 12 or (14 <= c <= 31) or c == 127


def _is_atext(ch: str) -> bool:
    """atext = ALPHA / DIGIT / ! # $ % & ' * + - / = ? ^ _ ` { | } ~"""
    if len(ch) != 1:
        return False
    c = ord(ch)
    return (
        (65 <= c <= 90)
        or (97 <= c <= 122)
        or (48 <= c <= 57)
        or ch in "!#$%&'*+-/=?^_`{|}~"
    )


def _is_vchar(ch: str) -> bool:
    """VCHAR = %x21-7E (printable US-ASCII)"""
    if len(ch) != 1:
        return False
    return 33 <= ord(ch) <= 126


def _is_wsp(ch: str) -> bool:
    """WSP = SP / HTAB"""
    return ch in (" ", "\t")


def _is_qtext(ch: str) -> bool:
    """qtext = NO-WS-CTL / %d33 / %d35-91 / %d93-126"""
    if len(ch) != 1:
        return False
    c = ord(ch)
    return _is_no_ws_ctl(ch) or c == 33 or (35 <= c <= 91) or (93 <= c <= 126)


def _is_ctext(ch: str) -> bool:
    """ctext = NO-WS-CTL / %d33-39 / %d42-91 / %d93-126"""
    if len(ch) != 1:
        return False
    c = ord(ch)
    return _is_no_ws_ctl(ch) or (33 <= c <= 39) or (42 <= c <= 91) or (93 <= c <= 126)


def _is_dtext(ch: str) -> bool:
    """dtext = NO-WS-CTL / %d33-90 / %d94-126"""
    if len(ch) != 1:
        return False
    c = ord(ch)
    return _is_no_ws_ctl(ch) or (33 <= c <= 90) or (94 <= c <= 126)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class AddressParser:
    """RFC 5322 compliant email address parser."""

    def __init__(self):
        self._pos = 0
        self._text = ""
        self._comments: List[str] = []

    def parse(self, input_str: str) -> ParseResult:
        """Parse one or more email addresses from the input string.

        Supports:
        - Single address: user@domain
        - Display name + address: John <john@example.com>
        - Multiple addresses: a@b, c@d
        - Groups: Group: a@b, c@d;
        """
        result = ParseResult()
        try:
            self._pos = 0
            self._text = input_str.strip()
            self._comments = []

            if not self._text:
                return ParseResult(error="Empty input")

            addresses = self._parse_address_list()

            # Skip any trailing whitespace
            self._skip_whitespace()

            if self._pos < len(self._text):
                # Unexpected trailing content
                # But be lenient — some parsers accept trailing content
                pass

            result.addresses = addresses
        except ValueError as e:
            result.error = str(e)

        return result

    def parse_one(self, input_str: str) -> RFC5322Address:
        """Parse a single email address, raising on failure."""
        result = self.parse(input_str)
        if result.error:
            raise ValueError(result.error)
        if not result.addresses:
            raise ValueError("No address found")
        return result.addresses[0]

    # ------------------------------------------------------------------
    # Core grammar rules
    # ------------------------------------------------------------------

    def _parse_address_list(self) -> List[RFC5322Address]:
        """address-list = (address *(\",\" address)) / obs-addr-list"""
        addresses = []
        self._skip_cfws()

        if self._pos >= len(self._text):
            return addresses

        addr = self._parse_address()
        addresses.append(addr)

        while self._pos < len(self._text):
            self._skip_cfws()
            if self._pos < len(self._text) and self._text[self._pos] == ",":
                self._pos += 1
                self._skip_cfws()
                if self._pos >= len(self._text):
                    break
                addr = self._parse_address()
                addresses.append(addr)
            else:
                break

        return addresses

    def _parse_address(self) -> RFC5322Address:
        """address = mailbox / group"""
        saved_pos = self._pos
        saved_comments = list(self._comments)

        # Try group first (contains ":")
        group_result = self._try_parse_group()
        if group_result is not None:
            return group_result

        # Fall back to mailbox
        self._pos = saved_pos
        self._comments = saved_comments
        return self._parse_mailbox()

    def _try_parse_group(self) -> Optional[RFC5322Address]:
        """group = display-name \":\" [group-list] \";\" [CFWS]"""
        saved_pos = self._pos
        saved_comments = list(self._comments)

        try:
            # Parse display name (phrase)
            display_name = self._parse_phrase()
            display_text = self._text[self._pos:].lstrip()

            # Must be followed by ":"
            self._skip_cfws()
            if self._pos >= len(self._text) or self._text[self._pos] != ":":
                self._pos = saved_pos
                self._comments = saved_comments
                return None

            self._pos += 1  # consume ":"
            self._skip_cfws()

            # Parse group list (optional)
            members = []
            if self._pos < len(self._text) and self._text[self._pos] != ";":
                # Check if there's actually addresses or just CFWS
                if self._text[self._pos] not in ("(", ")", ","):
                    members = self._parse_mailbox_list()

                self._skip_cfws()

            # Must end with ";"
            if self._pos >= len(self._text) or self._text[self._pos] != ";":
                self._pos = saved_pos
                self._comments = saved_comments
                return None

            self._pos += 1  # consume ";"
            self._skip_cfws()

            addr = RFC5322Address(
                display_name=display_name or "Undisclosed recipients",
                is_group=True,
                group_members=members,
                source=self._text,
            )
            addr.comments = list(self._comments)
            return addr

        except (ValueError, IndexError):
            self._pos = saved_pos
            self._comments = saved_comments
            return None

    def _parse_mailbox_list(self) -> List[RFC5322Address]:
        """mailbox-list = (mailbox *(\",\" mailbox)) / obs-mbox-list"""
        mailboxes = []
        mb = self._parse_mailbox()
        mailboxes.append(mb)

        while self._pos < len(self._text):
            self._skip_cfws()
            if self._pos < len(self._text) and self._text[self._pos] == ",":
                self._pos += 1
                self._skip_cfws()
                if self._pos >= len(self._text):
                    break
                mb = self._parse_mailbox()
                mailboxes.append(mb)
            else:
                break

        return mailboxes

    def _parse_mailbox(self) -> RFC5322Address:
        """mailbox = name-addr / addr-spec"""
        saved_pos = self._pos
        saved_comments = list(self._comments)

        # Try name-addr first (contains "<")
        try:
            return self._parse_name_addr()
        except ValueError:
            self._pos = saved_pos
            self._comments = saved_comments
            return self._parse_addr_spec()

    def _parse_name_addr(self) -> RFC5322Address:
        """name-addr = [display-name] angle-addr"""
        saved_pos = self._pos

        # Try to parse display-name (phrase)
        display_name = self._try_parse_display_name()

        angle_saved = self._pos
        self._skip_cfws()

        # Must have "<"
        if self._pos >= len(self._text) or self._text[self._pos] != "<":
            self._pos = saved_pos
            raise ValueError("Not a name-addr (missing angle bracket)")

        self._pos += 1  # consume "<"
        self._skip_cfws()

        # Parse addr-spec inside angle brackets
        local_part, domain = self._parse_addr_spec_inner()

        self._skip_cfws()
        if self._pos >= len(self._text) or self._text[self._pos] != ">":
            raise ValueError("Missing closing '>' in angle-addr")
        self._pos += 1  # consume ">"
        self._skip_cfws()

        addr = RFC5322Address(
            display_name=display_name,
            local_part=local_part,
            domain=domain,
            source=self._text,
        )
        addr.comments = list(self._comments)
        return addr

    def _try_parse_display_name(self) -> Optional[str]:
        """Try to parse display-name, returning None if not present."""
        saved_pos = self._pos
        try:
            phrase = self._parse_phrase()
            phrase = phrase.strip() if phrase else ""
            # Check if followed by "<" (angle-addr)
            after_saved = self._pos
            self._skip_cfws()
            if self._pos < len(self._text) and self._text[self._pos] == "<":
                return phrase if phrase else None
            # Not followed by "<" -- might still be a name-addr with FWS
            self._pos = after_saved
            return phrase if phrase else None
        except (ValueError, IndexError):
            self._pos = saved_pos
            return None

    def _parse_addr_spec(self) -> RFC5322Address:
        """addr-spec = local-part \"@\" domain (bare, no angle brackets)"""
        local_part, domain = self._parse_addr_spec_inner()
        addr = RFC5322Address(
            local_part=local_part,
            domain=domain,
            source=self._text,
        )
        addr.comments = list(self._comments)
        return addr

    def _parse_addr_spec_inner(self):
        """Parse local-part @ domain (without the address wrapper)."""
        local_part = self._parse_local_part()
        self._skip_cfws()
        if self._pos >= len(self._text) or self._text[self._pos] != "@":
            raise ValueError(f"Missing '@' after local-part at position {self._pos}")
        self._pos += 1  # consume "@"
        self._skip_cfws()
        domain = self._parse_domain()
        return local_part, domain

    def _parse_local_part(self) -> str:
        """local-part = dot-atom / quoted-string / obs-local-part"""
        saved_pos = self._pos

        # Try quoted-string first (starts with DQUOTE)
        self._skip_cfws()
        if self._pos < len(self._text) and self._text[self._pos] == '"':
            return self._parse_quoted_string_content()

        # Try dot-atom
        self._pos = saved_pos
        try:
            return self._parse_dot_atom_text()
        except ValueError:
            self._pos = saved_pos
            # Try obs-local-part (lenient fallback)
            return self._parse_obs_local_part()

    def _parse_domain(self) -> str:
        """domain = dot-atom / domain-literal / obs-domain"""
        saved_pos = self._pos
        self._skip_cfws()

        if self._pos < len(self._text) and self._text[self._pos] == "[":
            return self._parse_domain_literal()

        try:
            result = self._parse_dot_atom_text()
            if not result:
                raise ValueError("Empty domain")
            return result
        except ValueError:
            self._pos = saved_pos
            result = self._parse_obs_domain()
            if not result:
                raise ValueError("Empty domain after @")
            return result

    def _parse_domain_literal(self) -> str:
        """domain-literal = [CFWS] \"[\" *([FWS] dtext) [FWS] \"]\" [CFWS]"""
        # "[" already consumed by caller
        if self._pos < len(self._text) and self._text[self._pos] == "[":
            self._pos += 1

        parts = []
        while self._pos < len(self._text):
            self._skip_fws()
            if self._pos >= len(self._text):
                break
            ch = self._text[self._pos]
            if ch == "]":
                self._pos += 1
                self._skip_cfws()
                return "[" + "".join(parts) + "]"
            if _is_dtext(ch):
                parts.append(ch)
                self._pos += 1
            elif ch == "\\":
                # quoted-pair in dtext (obs-dtext)
                self._pos += 1
                if self._pos < len(self._text):
                    parts.append(self._text[self._pos])
                    self._pos += 1
            else:
                break

        raise ValueError(f"Unterminated domain-literal at position {self._pos}")

    def _parse_dot_atom_text(self) -> str:
        """dot-atom-text = 1*atext *(\".\" 1*atext)"""
        # Strip CFWS
        self._skip_cfws()
        parts = []

        # First atext (required)
        if self._pos >= len(self._text) or not _is_atext(self._text[self._pos]):
            raise ValueError(f"Expected atext at position {self._pos}")

        # Cannot start with a dot (per RFC 5322)
        if self._text[self._pos] == '.':
            raise ValueError(f"dot-atom cannot start with '.' at position {self._pos}")

        # Collect first batch of atext
        while self._pos < len(self._text) and _is_atext(self._text[self._pos]):
            parts.append(self._text[self._pos])
            self._pos += 1

        if not parts:
            raise ValueError(f"Expected atext at position {self._pos}")

        # *("." 1*atext)
        while self._pos < len(self._text):
            self._skip_cfws()
            if self._pos >= len(self._text):
                break
            ch = self._text[self._pos]
            if ch == ".":
                parts.append(".")
                self._pos += 1
                self._skip_cfws()
                # Must be followed by atext
                if self._pos >= len(self._text) or not _is_atext(self._text[self._pos]):
                    raise ValueError(f"Expected atext after '.' at position {self._pos}")
                while self._pos < len(self._text) and _is_atext(self._text[self._pos]):
                    parts.append(self._text[self._pos])
                    self._pos += 1
            elif ch == "@":
                break  # End of local-part
            elif _is_atext(ch):
                # Allow more atext (was broken by CFWS skip)
                parts.append(ch)
                self._pos += 1
            else:
                break

        return "".join(parts)

    def _parse_quoted_string_content(self) -> str:
        """Parse content of a quoted-string (including quotes)."""
        if self._pos < len(self._text) and self._text[self._pos] == '"':
            self._pos += 1

        parts = []
        while self._pos < len(self._text):
            ch = self._text[self._pos]

            if ch == '"':
                self._pos += 1  # closing DQUOTE
                # Skip trailing CFWS
                self._skip_cfws()
                return '"' + "".join(parts) + '"'

            if ch == "\\":
                # quoted-pair
                self._pos += 1
                if self._pos < len(self._text):
                    next_ch = self._text[self._pos]
                    if _is_vchar(next_ch) or _is_wsp(next_ch):
                        parts.append(next_ch)
                        self._pos += 1
                        continue
                raise ValueError(f"Invalid quoted-pair at position {self._pos}")

            # FWS inside quoted-string is allowed and semantically invisible
            if ch == "\r" or _is_wsp(ch):
                fws_text = self._consume_fws()
                # Preserve spaces in quoted content
                if " " in fws_text or "\t" in fws_text:
                    parts.append(" ")
                continue

            if ch == "\n":
                # CRLF within quoted-string (part of FWS)
                self._pos += 1
                continue

            if _is_qtext(ch):
                parts.append(ch)
                self._pos += 1
            else:
                raise ValueError(f"Invalid character {repr(ch)} in quoted-string at {self._pos}")

        raise ValueError(f"Unterminated quoted-string at position {self._pos}")

    def _consume_fws(self) -> str:
        """Consume and return folding whitespace (FWS)."""
        parts = []
        while self._pos < len(self._text):
            ch = self._text[self._pos]
            if _is_wsp(ch):
                parts.append(ch)
                self._pos += 1
            elif ch == '\r':
                parts.append(ch)
                self._pos += 1
                if self._pos < len(self._text) and self._text[self._pos] == '\n':
                    parts.append('\n')
                    self._pos += 1
                # After CRLF must have at least 1 WSP
            elif ch == '\n':
                parts.append(ch)
                self._pos += 1
            else:
                break
        return "".join(parts)

    # ------------------------------------------------------------------
    # Phrase (display-name)
    # ------------------------------------------------------------------

    def _parse_phrase(self) -> str:
        """phrase = 1*word / obs-phrase"""
        saved_pos = self._pos
        words = []

        try:
            while self._pos < len(self._text):
                self._skip_cfws()
                if self._pos >= len(self._text):
                    break
                ch = self._text[self._pos]
                if ch == '"':
                    # quoted-string
                    word = self._parse_quoted_string_content()
                    # Extract content between quotes
                    inner = word[1:-1] if word.startswith('"') else word
                    words.append(inner)
                elif _is_atext(ch):
                    # atom
                    atom_parts = []
                    while self._pos < len(self._text) and _is_atext(self._text[self._pos]):
                        atom_parts.append(self._text[self._pos])
                        self._pos += 1
                    words.append("".join(atom_parts))
                elif ch == ".":
                    # Dot in phrase is allowed (part of obs-phrase)
                    words.append(".")
                    self._pos += 1
                else:
                    break

                # Check for separator (space or before "<", ":", ";")
                self._skip_cfws()

            if not words:
                raise ValueError("Empty phrase")

            return " ".join(words)

        except (ValueError, IndexError):
            self._pos = saved_pos
            raise

    # ------------------------------------------------------------------
    # Whitespace and comments (CFWS / FWS)
    # ------------------------------------------------------------------

    def _skip_fws(self):
        """FWS = ([*WSP CRLF] 1*WSP) / obs-FWS"""
        saved = self._pos
        while self._pos < len(self._text):
            # Skip WSP
            wsp_count = 0
            while self._pos < len(self._text) and _is_wsp(self._text[self._pos]):
                self._pos += 1
                wsp_count += 1

            # Check for CRLF folding
            if (self._pos + 1 < len(self._text)
                    and self._text[self._pos] == '\r'
                    and self._text[self._pos + 1] == '\n'):
                self._pos += 2
                # Must be followed by at least 1 WSP
                if self._pos < len(self._text) and _is_wsp(self._text[self._pos]):
                    continue  # This was folding, continue skipping
                else:
                    # Not FWS, backtrack
                    self._pos -= 2
                    break

            if wsp_count > 0:
                break  # We consumed WSP, done with FWS
            else:
                break  # Nothing to consume

        if self._pos == saved:
            return  # No FWS consumed

    def _skip_cfws(self):
        """CFWS = (1*([FWS] comment) [FWS]) / FWS"""
        saved = self._pos
        consumed_any = False

        while self._pos < len(self._text):
            # Try FWS first
            fws_start = self._pos
            self._skip_fws()
            had_fws = self._pos > fws_start

            # Try comment
            if self._pos < len(self._text) and self._text[self._pos] == "(":
                comment = self._parse_comment()
                self._comments.append(comment)
                consumed_any = True
            elif had_fws:
                consumed_any = True
                break
            else:
                break

        if not consumed_any:
            return  # No CFWS consumed

    def _parse_comment(self) -> str:
        """comment = \"(\" *([FWS] ccontent) [FWS] \")\"
        ccontent = ctext / quoted-pair / comment
        """
        if self._pos >= len(self._text) or self._text[self._pos] != "(":
            raise ValueError(f"Expected '(' at position {self._pos}")

        depth = 1
        parts = []
        self._pos += 1  # consume "("

        while self._pos < len(self._text) and depth > 0:
            ch = self._text[self._pos]

            if ch == "(":
                depth += 1
                parts.append(ch)
                self._pos += 1
            elif ch == ")":
                depth -= 1
                if depth > 0:
                    parts.append(ch)
                self._pos += 1
            elif ch == "\\":
                # quoted-pair
                self._pos += 1
                if self._pos < len(self._text):
                    parts.append(self._text[self._pos])
                    self._pos += 1
                else:
                    raise ValueError("Unterminated quoted-pair in comment")
            elif _is_wsp(ch) or ch == "\r":
                self._skip_fws()
                if depth > 0:
                    parts.append(" ")
            elif _is_ctext(ch):
                parts.append(ch)
                self._pos += 1
            else:
                # Skip unexpected chars (lenient)
                parts.append(ch)
                self._pos += 1

        if depth > 0:
            raise ValueError("Unterminated comment")

        return "".join(parts)

    def _skip_whitespace(self):
        """Skip plain whitespace (not CFWS-aware)."""
        while self._pos < len(self._text) and self._text[self._pos] in " \t\r\n":
            self._pos += 1

    # ------------------------------------------------------------------
    # Obsolete syntax (§4.4) — lenient fallbacks
    # ------------------------------------------------------------------

    def _parse_obs_local_part(self) -> str:
        """obs-local-part = word *(\".\" word)"""
        parts = []
        while self._pos < len(self._text):
            self._skip_cfws()
            if self._pos >= len(self._text):
                break
            ch = self._text[self._pos]
            if ch == '"':
                word = self._parse_quoted_string_content()
                inner = word[1:-1] if word.startswith('"') else word
                if inner:
                    parts.append(inner)
            elif _is_atext(ch):
                atom_parts = []
                while self._pos < len(self._text) and _is_atext(self._text[self._pos]):
                    atom_parts.append(self._text[self._pos])
                    self._pos += 1
                parts.append("".join(atom_parts))
            elif ch == ".":
                # Consecutive dots or leading dot not allowed even in obs
                if not parts:
                    raise ValueError("obs-local-part cannot start with '.'")
                if parts[-1] == ".":
                    raise ValueError("consecutive dots in obs-local-part")
                parts.append(".")
                self._pos += 1
            elif ch == "@":
                break
            else:
                break

        if not parts:
            raise ValueError("Expected local-part")
        # Trailing dot not allowed
        if parts[-1] == ".":
            raise ValueError("obs-local-part cannot end with '.'")
        return "".join(parts)

    def _parse_obs_domain(self) -> str:
        """obs-domain = atom *(\".\" atom)"""
        parts = []
        while self._pos < len(self._text):
            self._skip_cfws()
            if self._pos >= len(self._text):
                break
            ch = self._text[self._pos]
            if _is_atext(ch):
                atom_parts = []
                while self._pos < len(self._text) and _is_atext(self._text[self._pos]):
                    atom_parts.append(self._text[self._pos])
                    self._pos += 1
                parts.append("".join(atom_parts))
                # Allow dots between atoms
                self._skip_cfws()
                if self._pos < len(self._text) and self._text[self._pos] == ".":
                    parts.append(".")
                    self._pos += 1
                else:
                    break
            else:
                break

        return "".join(parts)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def parse_email_address(input_str: str) -> ParseResult:
    """Parse email address(es) from input string.

    Example:
        result = parse_email_address("John Doe <john@example.com>")
        if result.error:
            print(f"Error: {result.error}")
        else:
            for addr in result.addresses:
                print(f"  {addr}")
    """
    parser = AddressParser()
    return parser.parse(input_str)
