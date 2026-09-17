#!/usr/bin/env python3
"""RFC 5322 Address Parser.

Implements the full ABNF grammar from RFC 5322 §3.2 (lexical tokens),
§3.4–§3.4.1 (address specification), and §4.4 (obsolete addressing).

strict=True (default) rejects all obs-* productions.
strict=False (permissive) accepts obsolete forms per §4.

Pure Python 3 stdlib — no external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Character classification helpers (matches RFC 5322 definitions)
# ---------------------------------------------------------------------------

# Printable US-ASCII (33-126)
_VCHAR = set(chr(c) for c in range(33, 127))

# White space: SP (32) and HTAB (9)
_WSP = {" ", "\t"}

# atext (§3.2.3): ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" /
# "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
_ATEXT = (
    set(chr(c) for c in range(65, 91))   # ALPHA uppercase
    | set(chr(c) for c in range(97, 123))  # ALPHA lowercase
    | set(chr(c) for c in range(48, 58))   # DIGIT
    | set("!#$%&'*+-/=?^_`{|}~")
)

# ctext (§3.2.2): %d33-39 / %d42-91 / %d93-126 / obs-ctext
_CTEXT = (
    set(chr(c) for c in range(33, 40))   # 33-39
    | set(chr(c) for c in range(42, 92))  # 42-91
    | set(chr(c) for c in range(93, 127)) # 93-126
)

# qtext (§3.2.4): %d33 / %d35-91 / %d93-126 / obs-qtext
_QTEXT = (
    set(chr(33))
    | set(chr(c) for c in range(35, 92))  # 35-91 (excludes 34=DQUOTE)
    | set(chr(c) for c in range(93, 127)) # 93-126
)

# dtext (§3.4.1): %d33-90 / %d94-126 / obs-dtext
_DTEXT = (
    set(chr(c) for c in range(33, 91))    # 33-90
    | set(chr(c) for c in range(94, 127)) # 94-126
)

# obs-NO-WS-CTL (§4.1): %d1-8 / %d11 / %d12 / %d14-31 / %d127
_OBS_NO_WS_CTL = (
    set(chr(c) for c in range(1, 9))
    | {chr(11), chr(12)}
    | set(chr(c) for c in range(14, 32))
    | {chr(127)}
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AddressParserError(ValueError):
    """Raised when an RFC 5322 address string cannot be parsed."""

    def __init__(self, message: str, pos: int = 0, context: str = ""):
        super().__init__(message)
        self.pos = pos
        self.context = context


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RFC5322Address:
    """Represents a parsed RFC 5322 address.

    Attributes:
        display_name: Optional display name (from name-addr or group).
        local_part: Local part of the addr-spec (before the @).
        domain: Domain part of the addr-spec (after the @).
        is_group: True if this is a group construct.
        group_mailboxes: List of member mailboxes (only for groups).
        raw: The raw input string for this address.
    """

    display_name: Optional[str] = None
    local_part: Optional[str] = None
    domain: Optional[str] = None
    is_group: bool = False
    group_mailboxes: List["RFC5322Address"] = field(default_factory=list)
    raw: str = ""

    def __repr__(self) -> str:
        if self.is_group:
            members = ", ".join(repr(m) for m in self.group_mailboxes)
            return (f"RFC5322Address(display_name={self.display_name!r}, "
                    f"is_group=True, group_mailboxes=[{members}])")
        return (f"RFC5322Address(display_name={self.display_name!r}, "
                f"local_part={self.local_part!r}, "
                f"domain={self.domain!r})")


# ===================================================================
# Parser
# ===================================================================

class AddressParser:
    """RFC 5322 address parser.

    Example:
        >>> parser = AddressParser(strict=True)
        >>> result = parser.parse("John Doe <jdoe@example.com>")
        >>> result.local_part
        'jdoe'
    """

    # Maximum characters per line (RFC 5322 §2.1.1)
    MAX_LINE_LENGTH = 998

    def __init__(self, strict: bool = True):
        """Initialise the parser.

        Args:
            strict: If True (default), reject all obs-* productions.
                    If False, accept obsolete syntax per §4.
        """
        self._strict = strict
        self._input: str = ""
        self._pos: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, text: str) -> RFC5322Address:
        """Parse a single address (mailbox or group).

        Args:
            text: Input string to parse.

        Returns:
            An RFC5322Address instance.

        Raises:
            AddressParserError: If parsing fails.
        """
        if len(text) > self.MAX_LINE_LENGTH:
            raise AddressParserError(
                f"Input exceeds {self.MAX_LINE_LENGTH} characters",
                pos=0, context=text[:40],
            )
        self._input = text
        self._pos = 0
        self._skip_cfws()
        addr = self._parse_address()
        self._skip_cfws()
        if self._pos < len(self._input):
            raise AddressParserError(
                f"Unexpected trailing character at {self._pos}: "
                f"{self._input[self._pos]!r}",
                pos=self._pos,
                context=self._input[max(0, self._pos - 10):self._pos + 10],
            )
        return addr

    def parse_address_list(self, text: str) -> List[RFC5322Address]:
        """Parse a list of addresses separated by commas.

        Args:
            text: Input string, e.g. "alice@a.com, bob@b.com".

        Returns:
            List of RFC5322Address instances.
        """
        if len(text) > self.MAX_LINE_LENGTH:
            raise AddressParserError(
                f"Input exceeds {self.MAX_LINE_LENGTH} characters",
            )
        self._input = text
        self._pos = 0
        self._skip_cfws()
        results = self._parse_address_list()
        self._skip_cfws()
        if self._pos < len(self._input):
            raise AddressParserError(
                f"Unexpected trailing character at {self._pos}: "
                f"{self._input[self._pos]!r}",
                pos=self._pos,
            )
        return results

    def parse_mailbox_list(self, text: str) -> List[RFC5322Address]:
        """Parse a list of mailboxes separated by commas.

        Args:
            text: Input string, e.g. "alice@a.com, bob@b.com".

        Returns:
            List of RFC5322Address instances (mailboxes only, no groups).
        """
        if len(text) > self.MAX_LINE_LENGTH:
            raise AddressParserError(
                f"Input exceeds {self.MAX_LINE_LENGTH} characters",
            )
        self._input = text
        self._pos = 0
        self._skip_cfws()
        results = self._parse_mailbox_list()
        self._skip_cfws()
        if self._pos < len(self._input):
            raise AddressParserError(
                f"Unexpected trailing character at {self._pos}: "
                f"{self._input[self._pos]!r}",
                pos=self._pos,
            )
        return results

    # ------------------------------------------------------------------
    # Peek / consume helpers
    # ------------------------------------------------------------------

    def _peek(self) -> str:
        """Return current character or '' if at end."""
        if self._pos < len(self._input):
            return self._input[self._pos]
        return ""

    def _consume(self) -> str:
        """Return current character and advance position."""
        ch = self._peek()
        if ch:
            self._pos += 1
        return ch

    def _expect(self, expected: str) -> str:
        """Consume and return the current character if it matches
        *expected*, else raise."""
        ch = self._peek()
        if ch != expected:
            raise AddressParserError(
                f"Expected {expected!r}, got {ch!r} at position {self._pos}",
                pos=self._pos,
                context=self._input[max(0, self._pos - 10):self._pos + 10],
            )
        self._pos += 1
        return ch

    # ------------------------------------------------------------------
    # §3.2.1  Quoted characters — quoted-pair
    # ------------------------------------------------------------------

    def _parse_quoted_pair(self) -> str:
        """Parse a quoted-pair; return the un-escaped character."""
        if self._peek() != "\\":
            raise AddressParserError(
                f"Expected backslash for quoted-pair at {self._pos}",
                pos=self._pos,
            )
        self._pos += 1
        ch = self._peek()
        if not ch:
            raise AddressParserError(
                "Unexpected end of input after backslash",
                pos=self._pos,
            )

        # Standard form: VCHAR or WSP
        if ch in _VCHAR or ch in _WSP:
            self._pos += 1
            return ch

        # obs-qp (only if permissive)
        if not self._strict:
            if ch == "\x00" or ch in _OBS_NO_WS_CTL or ch in ("\n", "\r"):
                self._pos += 1
                return ch

        raise AddressParserError(
            f"Invalid quoted-pair character {ch!r} at {self._pos}",
            pos=self._pos,
        )

    # ------------------------------------------------------------------
    # §3.2.2  Folding White Space and Comments — FWS, CFWS, comment
    # ------------------------------------------------------------------

    def _skip_fws(self) -> None:
        """Skip folding white space (FWS).

        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS

        The grammar breaks down as:
          1. Optional prefix: zero or more (*WSP CRLF) blocks
             (i.e. optional WSP before each CRLF).
          2. Mandatory 1*WSP (at least one space or tab).
          3. In permissive mode, obs-FWS appends: *(CRLF 1*WSP).
        """
        start = self._pos

        # -----------------------------------------------------------------
        # Step 1 — [*WSP CRLF]  (optional prefix)
        # Each iteration consumes one (*WSP CRLF) block.
        # Important: WSP that is NOT followed by CRLF must NOT be consumed
        # here – it is reserved for the mandatory 1*WSP below.
        # -----------------------------------------------------------------
        while True:
            saved = self._pos
            # optional WSP before CRLF
            while self._peek() in _WSP:
                self._pos += 1
            if self._has_crlf():
                self._pos += 2       # consumed *WSP CRLF
            else:
                self._pos = saved    # restore — no CRLF follows
                break

        # -----------------------------------------------------------------
        # Step 2 — 1*WSP  (mandatory – at least one space or tab)
        # -----------------------------------------------------------------
        if self._peek() not in _WSP:
            self._pos = start        # no FWS at all
            return

        while self._peek() in _WSP:
            self._pos += 1

        # -----------------------------------------------------------------
        # Step 3 — obs-FWS = *(CRLF 1*WSP)  (permissive mode only)
        # -----------------------------------------------------------------
        if not self._strict:
            while True:
                if self._has_crlf():
                    saved2 = self._pos
                    self._pos += 2
                    if self._peek() in _WSP:
                        while self._peek() in _WSP:
                            self._pos += 1
                    else:
                        self._pos = saved2
                        break
                else:
                    break

    def _has_crlf(self) -> bool:
        """Check if CRLF is at the current position."""
        return (
            self._pos + 1 < len(self._input)
            and self._input[self._pos] == "\r"
            and self._input[self._pos + 1] == "\n"
        )

    def _parse_comment(self) -> str:
        """Parse a comment: '(' *([FWS] ccontent) [FWS] ')'."""
        self._expect("(")
        content_parts: List[str] = []
        depth = 1

        while depth > 0 and self._pos < len(self._input):
            ch = self._peek()
            if ch == "(":
                depth += 1
                content_parts.append(self._consume())
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    self._consume()
                    break
                content_parts.append(self._consume())
            elif ch == "\\":
                try:
                    qp = self._parse_quoted_pair()
                    content_parts.append(qp)
                except AddressParserError:
                    content_parts.append(self._consume())
                    if self._peek():
                        content_parts.append(self._consume())
            elif ch in _WSP or ch == "\r":
                self._skip_fws()
                content_parts.append(" ")
            elif ch in _CTEXT:
                content_parts.append(self._consume())
            elif not self._strict and ch in _OBS_NO_WS_CTL:
                content_parts.append(self._consume())
            else:
                if not self._strict and ord(ch) < 128:
                    content_parts.append(self._consume())
                else:
                    raise AddressParserError(
                        f"Invalid ctext character {ch!r} at {self._pos}",
                        pos=self._pos,
                    )

        return "".join(content_parts)

    def _skip_cfws(self) -> None:
        """Skip comments and folding white space (CFWS).

        CFWS = (1*([FWS] comment) [FWS]) / FWS
        """
        while True:
            saved = self._pos
            self._skip_fws()
            if self._peek() == "(":
                self._parse_comment()
                self._skip_fws()
                saved = self._pos
            if self._pos == saved:
                break

    # ------------------------------------------------------------------
    # §3.2.3  Atom / dot-atom
    # ------------------------------------------------------------------

    def _parse_atom(self) -> str:
        """atom = [CFWS] 1*atext [CFWS]"""
        self._skip_cfws()
        text = self._parse_atext_run()
        if not text:
            raise AddressParserError(
                f"Expected atom at position {self._pos}",
                pos=self._pos,
            )
        self._skip_cfws()
        return text

    def _parse_atext_run(self) -> str:
        """Parse a run of 1*atext characters."""
        buf: List[str] = []
        while self._peek() in _ATEXT:
            buf.append(self._consume())
        return "".join(buf)

    def _parse_dot_atom_text(self) -> str:
        """dot-atom-text = 1*atext *("." 1*atext)"""
        part = self._parse_atext_run()
        if not part:
            raise AddressParserError(
                f"Expected dot-atom-text at position {self._pos}",
                pos=self._pos,
            )
        buf = [part]
        while self._peek() == ".":
            self._consume()          # consume the dot
            next_part = self._parse_atext_run()
            if not next_part:
                # Dot not followed by atext — invalid dot-atom-text.
                # Back up one character (the dot) so callers see what
                # stopped the parse, but signal failure so that
                # permissive mode can fall through to obs-* rules.
                self._pos -= 1
                raise AddressParserError(
                    f"Invalid dot-atom-text: trailing dot at {self._pos}",
                    pos=self._pos,
                )
            buf.append(".")
            buf.append(next_part)
        return "".join(buf)

    def _parse_dot_atom(self) -> str:
        """dot-atom = [CFWS] dot-atom-text [CFWS]"""
        self._skip_cfws()
        text = self._parse_dot_atom_text()
        self._skip_cfws()
        return text

    # ------------------------------------------------------------------
    # §3.2.4  Quoted Strings
    # ------------------------------------------------------------------

    def _parse_quoted_string(self) -> str:
        """Parse a quoted-string; return content between quotes.

        Per §3.2.4: CRLF inside FWS/CFWS within a quoted-string is
        semantically invisible, but WSP (SP / HTAB) is visible content
        and MUST be preserved in the result.
        """
        self._skip_cfws()
        self._expect('"')
        buf: List[str] = []
        while self._peek() and self._peek() != '"':
            # ---- strip invisible CRLF (keep WSP as visible content) ----
            while True:
                saved = self._pos
                while self._peek() in _WSP:
                    self._pos += 1
                if self._has_crlf():
                    self._pos += 2   # CRLF (and leading *WSP) is invisible
                else:
                    self._pos = saved  # restore WSP — it is visible content
                    break

            if self._peek() == '"':
                break

            # visible WSP (SP / HTAB)
            if self._peek() in _WSP:
                buf.append(self._consume())
                continue

            # qcontent
            if self._peek() == "\\":
                qp = self._parse_quoted_pair()
                buf.append(qp)
            elif self._peek() in _QTEXT:
                buf.append(self._consume())
            elif not self._strict and self._peek() in _OBS_NO_WS_CTL:
                buf.append(self._consume())
            else:
                if not self._strict and ord(self._peek()) < 128:
                    buf.append(self._consume())
                else:
                    raise AddressParserError(
                        f"Invalid qcontent char {self._peek()!r} at {self._pos}",
                        pos=self._pos,
                    )
        self._expect('"')
        self._skip_cfws()
        return "".join(buf)

    # ------------------------------------------------------------------
    # §3.2.5  Miscellaneous — word, phrase
    # ------------------------------------------------------------------

    def _parse_word(self) -> str:
        """word = atom / quoted-string"""
        saved = self._pos
        if self._peek() == '"':
            return self._parse_quoted_string()
        try:
            return self._parse_atom()
        except AddressParserError:
            self._pos = saved
            raise

    def _parse_phrase(self) -> str:
        """phrase = 1*word / obs-phrase

        In strict mode dots are only allowed when followed by a
        quoted-string or end-of-phrase (abbreviation style like ``Dr.``).
        A dot directly between two atoms (e.g. ``John.Doe``) is an
        obs-phrase production and is rejected.  In permissive mode dots
        between words are consumed silently.
        """
        words: List[str] = []
        saved = self._pos

        # ---- first word (mandatory) ----
        try:
            w = self._parse_word()
            words.append(w)
        except AddressParserError:
            # obs-phrase fallback (§4.1): word *(word / "." / CFWS)
            if not self._strict:
                self._pos = saved
                try:
                    first = self._parse_word()
                    words.append(first)
                except AddressParserError:
                    self._pos = saved
                    raise AddressParserError(
                        f"Expected phrase at position {self._pos}",
                        pos=self._pos,
                    )

                while True:
                    saved2 = self._pos
                    self._skip_cfws()
                    if self._peek() == ".":
                        self._consume()
                        continue
                    try:
                        w2 = self._parse_word()
                        words.append(w2)
                    except AddressParserError:
                        self._pos = saved2
                        break

                return " ".join(words)

            raise AddressParserError(
                f"Expected phrase at position {self._pos}",
                pos=self._pos,
            )

        # ---- additional words, with dot handling ----
        while True:
            saved2 = self._pos
            self._skip_cfws()
            if self._peek() == ".":
                dot_pos = self._pos
                self._consume()
                if self._strict:
                    # In strict mode, a dot directly between two atoms
                    # is obs-phrase — reject it.  Dots followed by a
                    # quoted-string or end-of-phrase are tolerated as
                    # trailing punctuation (e.g. ``Dr.``, ``Jr.``).
                    saved3 = self._pos
                    self._skip_cfws()
                    if self._peek() in _ATEXT:
                        raise AddressParserError(
                            f"Dot between atoms in phrase "
                            f"(obs-phrase) at position {dot_pos}",
                            pos=dot_pos,
                        )
                    self._pos = saved3
                    if words:
                        words[-1] = words[-1] + "."
                # In permissive mode dots are consumed silently
                continue
            try:
                w = self._parse_word()
                words.append(w)
            except AddressParserError:
                self._pos = saved2
                break

        return " ".join(words)

    # ------------------------------------------------------------------
    # §3.4  Address Specification
    # ------------------------------------------------------------------

    def _parse_address(self) -> RFC5322Address:
        """address = mailbox / group"""
        saved = self._pos
        try:
            return self._parse_group()
        except AddressParserError:
            self._pos = saved
            return self._parse_mailbox()

    def _parse_mailbox(self) -> RFC5322Address:
        """mailbox = name-addr / addr-spec"""
        saved = self._pos

        # Look-ahead: scan for '<' before '@' to detect name-addr
        brace_pos = -1
        at_pos = -1
        i = self._pos
        in_quote = False
        depth = 0
        while i < len(self._input):
            ch = self._input[i]
            if in_quote:
                if ch == '\\':
                    i += 2
                    continue
                if ch == '"':
                    in_quote = False
            elif depth > 0:
                if ch == '(':
                    depth += 1
                elif ch == ')':
                    depth -= 1
                elif ch == '\\':
                    i += 2
                    continue
            else:
                if ch == '"':
                    in_quote = True
                elif ch == '(':
                    depth = 1
                elif ch == '<':
                    brace_pos = i
                    break
                elif ch == '@':
                    at_pos = i
                    break
                elif ch in (',', ';', '>', ':'):
                    break
            i += 1

        # name-addr detection
        is_name_addr = brace_pos >= 0 and (at_pos < 0 or brace_pos < at_pos)

        if is_name_addr:
            try:
                return self._parse_name_addr()
            except AddressParserError:
                self._pos = saved
                raise

        # Try name-addr (bare <addr-spec> case)
        try:
            return self._parse_name_addr()
        except AddressParserError:
            self._pos = saved
            return self._parse_addr_spec_mailbox()

    def _parse_name_addr(self) -> RFC5322Address:
        """name-addr = [display-name] angle-addr"""
        saved = self._pos
        display_name = None

        if self._peek() != "<":
            before = self._pos
            try:
                display_name = self._parse_phrase()
            except AddressParserError:
                # When the phrase partially consumed input (e.g. an
                # obs-phrase dot between atoms was rejected in strict
                # mode) do NOT fall through to bare angle-addr — let
                # the error propagate so the caller sees the real
                # reason the input was rejected.
                if self._pos != before:
                    raise
                self._pos = saved

        angle = self._parse_angle_addr()
        result = RFC5322Address(
            display_name=display_name,
            local_part=angle.local_part,
            domain=angle.domain,
            raw=self._input[saved:self._pos],
        )
        return result

    def _parse_angle_addr(self) -> RFC5322Address:
        """angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr"""
        saved = self._pos
        self._skip_cfws()

        if self._peek() != "<":
            raise AddressParserError(
                f"Expected '<' at position {self._pos}",
                pos=self._pos,
            )

        self._consume()          # "<"
        self._skip_cfws()
        saved2 = self._pos       # position after "<" CFWS

        # ---- standard path: "<" addr-spec ">" ----
        try:
            addr = self._parse_addr_spec()
            self._skip_cfws()
            self._expect(">")
            self._skip_cfws()
            addr.raw = self._input[saved:self._pos]
            return addr
        except AddressParserError:
            # ---- obs-angle-addr (§4.4): "<" obs-route addr-spec ">" ----
            if not self._strict:
                self._pos = saved2
                self._parse_obs_route()
                addr = self._parse_addr_spec()
                self._skip_cfws()
                self._expect(">")
                self._skip_cfws()
                addr.raw = self._input[saved:self._pos]
                return addr
            raise

    def _parse_group(self) -> RFC5322Address:
        """group = display-name ":" [group-list] ";" [CFWS]"""
        saved = self._pos
        display_name = self._parse_phrase()
        self._skip_cfws()

        if self._peek() != ":":
            raise AddressParserError(
                f"Expected ':' for group at position {self._pos}",
                pos=self._pos,
            )
        self._consume()          # ":"
        saved_after_colon = self._pos
        self._skip_cfws()

        group_list: List[RFC5322Address] = []

        if self._peek() == ";":
            pass
        elif self._try_group_semicolon_after_cfws():
            pass
        else:
            try:
                group_list = self._parse_mailbox_list()
            except AddressParserError:
                if not self._strict:
                    self._pos = saved_after_colon
                    self._parse_obs_group_list()
                else:
                    raise

        self._skip_cfws()
        self._expect(";")
        self._skip_cfws()

        return RFC5322Address(
            display_name=display_name,
            is_group=True,
            group_mailboxes=group_list,
            raw=self._input[saved:self._pos],
        )

    def _try_group_semicolon_after_cfws(self) -> bool:
        """Check if CFWS then ';' follows (empty group-list)."""
        saved = self._pos
        self._skip_cfws()
        if self._peek() == ";":
            return True
        self._pos = saved
        return False

    # ------------------------------------------------------------------
    # Lists
    # ------------------------------------------------------------------

    def _parse_address_list(self) -> List[RFC5322Address]:
        """address-list = ..."""
        saved = self._pos
        try:
            return self._parse_standard_address_list()
        except AddressParserError:
            if not self._strict:
                self._pos = saved
                return self._parse_obs_addr_list()
            raise

    def _parse_standard_address_list(self) -> List[RFC5322Address]:
        results: List[RFC5322Address] = []
        results.append(self._parse_address())
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
            results.append(self._parse_address())
            self._skip_cfws()
        return results

    def _parse_mailbox_list(self) -> List[RFC5322Address]:
        saved = self._pos
        try:
            return self._parse_standard_mailbox_list()
        except AddressParserError:
            if not self._strict:
                self._pos = saved
                return self._parse_obs_mbox_list()
            raise

    def _parse_standard_mailbox_list(self) -> List[RFC5322Address]:
        results: List[RFC5322Address] = []
        results.append(self._parse_mailbox())
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
            results.append(self._parse_mailbox())
            self._skip_cfws()
        return results

    # ------------------------------------------------------------------
    # §3.4.1  Addr-Spec
    # ------------------------------------------------------------------

    def _parse_addr_spec(self) -> RFC5322Address:
        saved = self._pos
        local_part = self._parse_local_part()
        self._skip_cfws()
        self._expect("@")
        self._skip_cfws()
        domain = self._parse_domain()
        return RFC5322Address(
            local_part=local_part,
            domain=domain,
            raw=self._input[saved:self._pos],
        )

    def _parse_addr_spec_mailbox(self) -> RFC5322Address:
        saved = self._pos
        addr = self._parse_addr_spec()
        addr.raw = self._input[saved:self._pos]
        return addr

    def _parse_local_part(self) -> str:
        saved = self._pos
        # In permissive mode delegate to obs-local-part for mixed
        # forms like  "hello"."world"  or  hello."world"  where
        # strict dot-atom or a bare quoted-string would stop short.
        if not self._strict:
            return self._parse_obs_local_part()
        if self._peek() == '"':
            return self._parse_quoted_string()
        try:
            return self._parse_dot_atom()
        except AddressParserError:
            if not self._strict:
                self._pos = saved
                return self._parse_obs_local_part()
            raise

    def _parse_domain(self) -> str:
        saved = self._pos
        if self._peek() == "[":
            return self._parse_domain_literal()
        try:
            return self._parse_dot_atom()
        except AddressParserError:
            if not self._strict:
                self._pos = saved
                return self._parse_obs_domain()
            raise

    # ------------------------------------------------------------------
    # domain-literal
    # ------------------------------------------------------------------

    def _parse_domain_literal(self) -> str:
        saved = self._pos
        self._skip_cfws()
        self._expect("[")
        buf: List[str] = []
        while self._peek() and self._peek() != "]":
            self._skip_cfws()
            if self._peek() == "]":
                break
            if self._peek() in _DTEXT:
                buf.append(self._consume())
            elif self._peek() == "\\":
                if not self._strict:
                    try:
                        qp = self._parse_quoted_pair()
                        buf.append(qp)
                    except AddressParserError:
                        buf.append(self._consume())
                        if self._peek():
                            buf.append(self._consume())
                else:
                    raise AddressParserError(
                        f"Invalid dtext char {self._peek()!r} at {self._pos}",
                        pos=self._pos,
                    )
            elif not self._strict and self._peek() in _OBS_NO_WS_CTL:
                buf.append(self._consume())
            else:
                raise AddressParserError(
                    f"Invalid dtext char {self._peek()!r} at {self._pos}",
                    pos=self._pos,
                )
        self._skip_cfws()
        self._expect("]")
        self._skip_cfws()
        return "[" + "".join(buf) + "]"

    # ------------------------------------------------------------------
    # §4.4  Obsolete Addressing
    # ------------------------------------------------------------------

    def _parse_obs_route(self) -> None:
        """obs-route = obs-domain-list ':'"""
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
        self._expect("@")
        self._parse_domain()
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
            if self._peek() == "@":
                self._consume()
                self._parse_domain()
                self._skip_cfws()
        self._expect(":")

    def _parse_obs_mbox_list(self) -> List[RFC5322Address]:
        results: List[RFC5322Address] = []
        while True:
            saved = self._pos
            self._skip_cfws()
            if self._peek() == ",":
                self._consume()
            else:
                self._pos = saved
                break
        results.append(self._parse_mailbox())
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
            saved2 = self._pos
            self._skip_cfws()
            if self._peek() in (",", ";") or self._pos >= len(self._input):
                continue
            self._pos = saved2
            try:
                results.append(self._parse_mailbox())
            except AddressParserError:
                self._pos = saved2
                self._skip_cfws()
            self._skip_cfws()
        return results

    def _parse_obs_addr_list(self) -> List[RFC5322Address]:
        results: List[RFC5322Address] = []
        while True:
            saved = self._pos
            self._skip_cfws()
            if self._peek() == ",":
                self._consume()
            else:
                self._pos = saved
                break
        results.append(self._parse_address())
        self._skip_cfws()
        while self._peek() == ",":
            self._consume()
            self._skip_cfws()
            saved2 = self._pos
            self._skip_cfws()
            if self._peek() in (",", ";") or self._pos >= len(self._input):
                continue
            self._pos = saved2
            try:
                results.append(self._parse_address())
            except AddressParserError:
                self._pos = saved2
                self._skip_cfws()
            self._skip_cfws()
        return results

    def _parse_obs_group_list(self) -> None:
        """obs-group-list = 1*([CFWS] ',') [CFWS]"""
        count = 0
        while True:
            self._skip_cfws()
            if self._peek() == ",":
                self._consume()
                count += 1
            else:
                break
        if count == 0:
            raise AddressParserError(
                f"Expected obs-group-list at position {self._pos}",
                pos=self._pos,
            )
        self._skip_cfws()

    def _parse_obs_local_part(self) -> str:
        """obs-local-part = word *('.' word)"""
        words: List[str] = []
        words.append(self._parse_word())
        while self._peek() == ".":
            saved = self._pos
            self._consume()
            try:
                words.append(".")
                words.append(self._parse_word())
            except AddressParserError:
                self._pos = saved
                break
        return "".join(words)

    def _parse_obs_domain(self) -> str:
        """obs-domain = atom *('.' atom)"""
        atoms: List[str] = []
        atoms.append(self._parse_atom())
        while self._peek() == ".":
            saved = self._pos
            self._consume()
            try:
                atoms.append(".")
                atoms.append(self._parse_atom())
            except AddressParserError:
                self._pos = saved
                break
        return "".join(atoms)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def parse_address(text: str, strict: bool = True) -> RFC5322Address:
    """Parse a single RFC 5322 address (mailbox or group)."""
    parser = AddressParser(strict=strict)
    return parser.parse(text)


def parse_address_list(text: str, strict: bool = True) -> List[RFC5322Address]:
    """Parse an RFC 5322 address list (comma-separated addresses)."""
    parser = AddressParser(strict=strict)
    return parser.parse_address_list(text)


def parse_mailbox_list(text: str, strict: bool = True) -> List[RFC5322Address]:
    """Parse an RFC 5322 mailbox list (comma-separated mailboxes)."""
    parser = AddressParser(strict=strict)
    return parser.parse_mailbox_list(text)
