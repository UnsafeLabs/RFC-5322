"""
RFC 5322 Email Address Parser

Implements full ABNF grammar from sections 3.2-3.4 with optional
obsolete syntax support from section 4.4.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, Tuple


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: Optional[str]
    local_part: str
    domain: str
    is_group: bool
    group_members: List['RFC5322Address']
    comments: List[str]
    source: str


class ParseError(Exception):
    """Raised when parsing fails."""
    pass


class AddressParser:
    def __init__(self, strict: bool = True):
        self.strict = strict
        self._comments: List[str] = []
        self._input = ""
        self._pos = 0

    def parse(self, raw: str) -> RFC5322Address:
        self._input = raw
        self._pos = 0
        self._comments = []
        try:
            address = self._address()
            if self._pos != len(self._input):
                raise ParseError(
                    f"Unexpected trailing content at position {self._pos}"
                )
            return address
        except ParseError:
            raise
        except Exception as e:
            raise ParseError(
                f"Parse error at position {self._pos}: {e}"
            )

    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        addresses: List[RFC5322Address] = []
        self._input = raw
        self._pos = 0
        self._comments = []
        while self._pos < len(self._input):
            self._skip_cfws()
            if self._pos >= len(self._input):
                break
            # Handle leading/trailing/double commas (obs-mbox-list)
            if self._input[self._pos] == ',':
                if not self.strict:
                    self._pos += 1
                    continue
                else:
                    break
            try:
                addr = self._address()
            except ParseError:
                if not self.strict:
                    break
                raise
            addresses.append(addr)
            self._skip_cfws()
            if self._pos < len(self._input) and self._peek() == ',':
                self._advance()
            else:
                break
        return addresses

    def parse_mailbox_list(self, raw: str) -> List[RFC5322Address]:
        return self.parse_address_list(raw)

    # ── Internal helpers ──────────────────────────────────────────

    def _peek(self) -> str:
        return self._input[self._pos]

    def _advance(self) -> str:
        ch = self._input[self._pos]
        self._pos += 1
        return ch

    def _at_end(self) -> bool:
        return self._pos >= len(self._input)

    def _match(self, ch: str) -> bool:
        if not self._at_end() and self._input[self._pos] == ch:
            self._pos += 1
            return True
        return False

    def _expect(self, ch: str):
        if not self._match(ch):
            raise ParseError(
                f"Expected '{ch}' at position {self._pos}"
            )

    def _raw_slice(self, start: int) -> str:
        return self._input[start:self._pos]

    # ── Section 3.2.1: quoted-pair ───────────────────────────────

    def _quoted_pair(self) -> str:
        self._expect('\\')
        if self._at_end():
            raise ParseError("Unexpected end after backslash")
        ch = self._advance()
        if self.strict:
            if not (33 <= ord(ch) <= 126 or ch in (' ', '\t')):
                raise ParseError(
                    f"Invalid character in quoted-pair: {ch!r}"
                )
        return ch

    # ── Section 3.2.2: FWS, comment, CFWS ───────────────────────

    def _wsp(self) -> bool:
        if not self._at_end() and self._input[self._pos] in (' ', '\t'):
            self._pos += 1
            return True
        return False

    def _crlf(self) -> bool:
        if (self._pos + 1 < len(self._input)
                and self._input[self._pos:self._pos + 2] == '\r\n'):
            self._pos += 2
            return True
        return False

    def _fws(self) -> bool:
        # FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        save = self._pos
        wsp_start = self._pos
        while self._wsp():
            pass
        has_crlf = self._crlf()
        if has_crlf:
            if self._wsp():
                while self._wsp():
                    pass
                return True
            self._pos = save
            return False
        else:
            if self._pos > wsp_start:
                return True
        self._pos = save
        if not self.strict:
            return self._obs_fws()
        return False

    def _obs_fws(self) -> bool:
        if not self._wsp():
            return False
        while self._wsp():
            pass
        while True:
            save = self._pos
            if self._crlf() and self._wsp():
                while self._wsp():
                    pass
            else:
                self._pos = save
                break
        return True

    def _ctext(self) -> bool:
        if self._at_end():
            return False
        code = ord(self._input[self._pos])
        if (33 <= code <= 39) or (42 <= code <= 91) or (93 <= code <= 126):
            self._pos += 1
            return True
        if not self.strict:
            return self._obs_ctext()
        return False

    def _obs_ctext(self) -> bool:
        if self._at_end():
            return False
        code = ord(self._input[self._pos])
        if ((1 <= code <= 8) or code == 11 or code == 12
                or (14 <= code <= 31) or code == 127):
            self._pos += 1
            return True
        return False

    def _ccontent(self) -> str:
        content = ""
        while not self._at_end():
            if (self._input[self._pos] == '\\'
                    and (self._pos + 1 < len(self._input))):
                content += self._quoted_pair()
            elif self._input[self._pos] == '(':
                content += self._comment()
            elif self._ctext():
                content += self._input[self._pos - 1]
            else:
                break
        return content

    def _comment(self) -> str:
        self._expect('(')
        content = ""
        while not self._at_end():
            self._fws()
            if self._at_end() or self._input[self._pos] == ')':
                break
            content += self._ccontent()
        self._expect(')')
        self._comments.append(content)
        return f"({content})"

    def _skip_cfws(self):
        while not self._at_end():
            self._fws()
            if self._at_end() or self._input[self._pos] != '(':
                break
            self._comment()

    # ── Section 3.2.3: atom, dot-atom ────────────────────────────

    def _atext(self) -> bool:
        if self._at_end():
            return False
        ch = self._input[self._pos]
        if ch.isalnum() or ch in "!#$%&'*+-/=?^_`{|}~":
            self._pos += 1
            return True
        return False

    def _atom(self) -> str:
        self._skip_cfws()
        start = self._pos
        while self._atext():
            pass
        if self._pos == start:
            raise ParseError(
                f"Expected atom at position {self._pos}"
            )
        atom = self._raw_slice(start)
        self._skip_cfws()
        return atom

    def _dot_atom_text(self) -> str:
        start = self._pos
        if not self._atext():
            raise ParseError(
                f"Expected atext at position {self._pos}"
            )
        while self._atext():
            pass
        result = self._raw_slice(start)
        while not self._at_end() and self._input[self._pos] == '.':
            dot_start = self._pos
            self._pos += 1
            if not self._atext():
                self._pos = dot_start
                break
            while self._atext():
                pass
            result += self._raw_slice(dot_start)
        return result

    def _dot_atom(self) -> str:
        self._skip_cfws()
        result = self._dot_atom_text()
        self._skip_cfws()
        return result

    def _raw_word(self) -> str:
        """Return raw text of a word without semantic stripping."""
        save = self._pos
        self._word()
        return self._raw_slice(save)

    # ── Section 3.2.4: quoted-string ─────────────────────────────

    def _qtext(self) -> bool:
        if self._at_end():
            return False
        code = ord(self._input[self._pos])
        if code == 33 or (35 <= code <= 91) or (93 <= code <= 126):
            self._pos += 1
            return True
        if not self.strict:
            return self._obs_qtext()
        return False

    def _obs_qtext(self) -> bool:
        if self._at_end():
            return False
        code = ord(self._input[self._pos])
        if ((1 <= code <= 8) or code == 11 or code == 12
                or (14 <= code <= 31) or code == 127):
            self._pos += 1
            return True
        return False

    def _qcontent(self) -> str:
        if self._at_end():
            raise ParseError("Unexpected end in quoted-string")
        if (self._input[self._pos] == '\\'
                and (self._pos + 1 < len(self._input))):
            return self._quoted_pair()
        elif self._qtext():
            return self._input[self._pos - 1]
        else:
            raise ParseError(
                f"Invalid qcontent at position {self._pos}"
            )

    def _quoted_string(self) -> str:
        self._skip_cfws()
        self._expect('"')
        content = ""
        while not self._at_end():
            # Capture FWS and preserve WSP in content
            fws_start = self._pos
            self._fws()
            fws_text = self._input[fws_start:self._pos]
            if self._at_end() or self._input[self._pos] == '"':
                break
            # Normalize FWS: remove CRLF, keep WSP
            if fws_text:
                normalized = fws_text.replace('\r\n', '')
                if normalized:
                    content += normalized
            content += self._qcontent()
        self._expect('"')
        self._skip_cfws()
        return content

    # ── Section 3.2.5: word, phrase ──────────────────────────────

    def _word(self) -> str:
        if self._at_end():
            raise ParseError("Unexpected end, expected word")
        if self._input[self._pos] == '"':
            return self._quoted_string()
        return self._atom()

    def _phrase(self) -> str:
        words = [self._word()]
        while not self._at_end():
            try:
                words.append(self._word())
            except ParseError:
                break
        if not self.strict:
            while not self._at_end():
                if self._input[self._pos] == '.':
                    words.append('.')
                    self._pos += 1
                    try:
                        words.append(self._word())
                    except ParseError:
                        break
                else:
                    break
        # Join words with spaces, but dots attach to adjacent words
        result = ""
        for i, w in enumerate(words):
            if w == '.':
                result += '.'
            elif i > 0 and words[i - 1] == '.':
                result += ' ' + w
            elif i > 0:
                result += ' ' + w
            else:
                result = w
        return result

    # ── Section 3.4: address, mailbox, group ─────────────────────

    def _address(self) -> RFC5322Address:
        save = self._pos
        save_comments = self._comments[:]
        try:
            return self._group()
        except ParseError:
            self._pos = save
            self._comments = save_comments
        return self._mailbox()

    def _mailbox(self) -> RFC5322Address:
        save = self._pos
        save_comments = self._comments[:]
        try:
            return self._name_addr()
        except ParseError:
            self._pos = save
            self._comments = save_comments
        # In non-strict mode, try obs-angle-addr
        if not self.strict:
            save2 = self._pos
            save2_comments = self._comments[:]
            try:
                return self._obs_angle_addr_mailbox()
            except ParseError:
                self._pos = save2
                self._comments = save2_comments
        return self._addr_spec_as_mailbox()

    def _obs_angle_addr_mailbox(self) -> RFC5322Address:
        """Parse obs-angle-addr as a mailbox (with route)."""
        self._skip_cfws()
        self._expect('<')
        # Parse obs-route
        self._obs_route()
        local, domain = self._addr_spec()
        self._expect('>')
        self._skip_cfws()
        return RFC5322Address(
            display_name=None,
            local_part=local,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=self._comments[:],
            source="",
        )

    def _name_addr(self) -> RFC5322Address:
        save = self._pos
        save_comments = self._comments[:]
        display_name = None
        if not self._at_end() and self._input[self._pos] != '<':
            try:
                display_name = self._phrase()
            except ParseError:
                self._pos = save
                self._comments = save_comments
                display_name = None
        local, domain = self._angle_addr()
        return RFC5322Address(
            display_name=display_name,
            local_part=local,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=self._comments[:],
            source="",
        )

    def _angle_addr(self) -> Tuple[str, str]:
        self._skip_cfws()
        self._expect('<')
        local, domain = self._addr_spec()
        self._expect('>')
        self._skip_cfws()
        return local, domain

    def _group(self) -> RFC5322Address:
        display_name = self._phrase()
        self._expect(':')
        members: List[RFC5322Address] = []
        self._skip_cfws()
        if not self._at_end() and self._input[self._pos] != ';':
            members = self._group_list()
        self._expect(';')
        self._skip_cfws()
        return RFC5322Address(
            display_name=display_name,
            local_part="",
            domain="",
            is_group=True,
            group_members=members,
            comments=self._comments[:],
            source="",
        )

    def _group_list(self) -> List[RFC5322Address]:
        try:
            return self._mailbox_list_internal()
        except ParseError:
            pass
        self._skip_cfws()
        return []

    def _mailbox_list_internal(self) -> List[RFC5322Address]:
        members = [self._mailbox()]
        while not self._at_end():
            self._skip_cfws()
            if self._at_end() or self._input[self._pos] != ',':
                break
            self._advance()
            if not self.strict:
                self._skip_cfws()
                if (self._at_end()
                        or self._input[self._pos] in (',', ';')):
                    continue
            members.append(self._mailbox())
        return members

    def _addr_spec_as_mailbox(self) -> RFC5322Address:
        local, domain = self._addr_spec()
        return RFC5322Address(
            display_name=None,
            local_part=local,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=self._comments[:],
            source="",
        )

    def _addr_spec(self) -> Tuple[str, str]:
        local = self._local_part()
        self._expect('@')
        domain = self._domain()
        return local, domain

    # ── Section 3.4.1: local-part, domain, domain-literal ────────

    def _local_part(self) -> str:
        save = self._pos
        save_comments = self._comments[:]

        # Try dot-atom first; check if followed by @
        try:
            result = self._dot_atom()
            if not self._at_end() and self._input[self._pos] == '@':
                return result
            # dot_atom succeeded but not followed by @, try obs-local-part
            if not self.strict:
                self._pos = save
                self._comments = save_comments
                return self._obs_local_part()
            # In strict mode, dot_atom without @ is still an error
            raise ParseError(
                f"Expected '@' at position {self._pos}"
            )
        except ParseError:
            self._pos = save
            self._comments = save_comments

        # Try quoted-string
        if not self._at_end() and self._input[self._pos] == '"':
            return self._quoted_string()

        # Try obs-local-part if not strict
        if not self.strict:
            return self._obs_local_part()

        raise ParseError(
            f"Invalid local-part at position {self._pos}"
        )

    def _domain(self) -> str:
        save = self._pos
        save_comments = self._comments[:]
        if not self._at_end() and self._input[self._pos] == '[':
            return self._domain_literal()
        try:
            result = self._dot_atom()
            if not self._at_end() and self._input[self._pos] in ('@', '>'):
                return result
            if not self.strict:
                self._pos = save
                self._comments = save_comments
                return self._obs_domain()
            return result
        except ParseError:
            self._pos = save
            self._comments = save_comments
        if not self.strict:
            return self._obs_domain()
        raise ParseError(
            f"Invalid domain at position {self._pos}"
        )

    def _domain_literal(self) -> str:
        self._skip_cfws()
        self._expect('[')
        content = ""
        while not self._at_end():
            fws_start = self._pos
            self._fws()
            fws_text = self._input[fws_start:self._pos]
            if self._at_end() or self._input[self._pos] == ']':
                break
            content += fws_text
            content += self._dtext()
        self._expect(']')
        self._skip_cfws()
        return f"[{content}]"

    def _dtext(self) -> str:
        if self._at_end():
            raise ParseError("Unexpected end in domain literal")
        ch = self._input[self._pos]
        code = ord(ch)
        if (33 <= code <= 90) or (94 <= code <= 126):
            self._pos += 1
            return ch
        if not self.strict:
            return self._obs_dtext()
        raise ParseError(f"Invalid dtext character: {ch!r}")

    def _obs_dtext(self) -> str:
        if self._at_end():
            raise ParseError("Unexpected end in obs-dtext")
        code = ord(self._input[self._pos])
        if ((1 <= code <= 8) or code == 11 or code == 12
                or (14 <= code <= 31) or code == 127):
            self._pos += 1
            return self._input[self._pos - 1]
        if self._input[self._pos] == '\\':
            return self._quoted_pair()
        raise ParseError(
            f"Invalid obs-dtext at position {self._pos}"
        )

    # ── Section 4.4: obsolete addressing ─────────────────────────

    def _obs_local_part(self) -> str:
        """obs-local-part = word *("." word) - returns raw text."""
        start = self._pos
        self._word()
        while not self._at_end():
            self._skip_cfws()
            if self._at_end() or self._input[self._pos] != '.':
                break
            self._pos += 1
            self._skip_cfws()
            self._word()
        return self._raw_slice(start)

    def _obs_domain(self) -> str:
        """obs-domain = atom *("." atom) - returns raw text."""
        start = self._pos
        self._atom()
        while not self._at_end():
            self._skip_cfws()
            if self._at_end() or self._input[self._pos] != '.':
                break
            self._pos += 1
            self._skip_cfws()
            self._atom()
        return self._raw_slice(start)

    def _obs_route(self):
        # obs-route = obs-domain-list ":"
        self._obs_domain_list()
        self._expect(':')

    def _obs_domain_list(self):
        """obs-domain-list = *(CFWS / ",") "@" domain ..."""
        while not self._at_end():
            if self._input[self._pos] in (' ', '\t', '('):
                self._skip_cfws()
            elif self._input[self._pos] == ',':
                self._pos += 1
            elif self._input[self._pos] == '@':
                self._pos += 1
                self._domain()
                break
            else:
                break
        while not self._at_end() and self._input[self._pos] == ',':
            self._pos += 1
            self._skip_cfws()
            if (not self._at_end()
                    and self._input[self._pos] == '@'):
                self._pos += 1
                self._domain()
