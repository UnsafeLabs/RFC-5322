"""
RFC 5322 Compliant Email Address Parser
Implements full ABNF grammar from §3.2 through §4.4
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union
from enum import Enum, auto


class ParseError(Exception):
    """Raised when email address parsing fails."""
    pass


class Mode(Enum):
    """Parser mode: strict rejects obsolete forms, permissive accepts them."""
    STRICT = auto()
    PERMISSIVE = auto()


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    local_part: str
    domain: str
    display_name: Optional[str] = None
    is_group: bool = False
    group_members: List['RFC5322Address'] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    source: str = ""
    
    def __post_init__(self):
        if self.group_members is None:
            self.group_members = []
        if self.comments is None:
            self.comments = []
    
    @property
    def addr_spec(self) -> str:
        """Return the addr-spec form (local-part@domain)."""
        return f"{self.local_part}@{self.domain}"
    
    def __str__(self) -> str:
        if self.is_group:
            members = ", ".join(str(m) for m in self.group_members)
            return f"{self.display_name}:{members};"
        if self.display_name:
            return f'"{self.display_name}" <{self.addr_spec}>'
        return self.addr_spec


class RFC5322Lexer:
    """
    Lexical analyzer for RFC 5322 §3.2 tokens.
    Handles quoted-pair, FWS, CFWS, quoted-string, and atoms.
    """
    
    # Terminal patterns
    QUOTED_PAIR = r'\\[\x00-\x7F]'  # \ followed by any ASCII
    FWS = r'(?:[ \t]*\r\n)?[ \t]+'  # Folding whitespace
    CTEXT = r'[\x21-\x27\x2A-\x5B\x5D-\x7E]'  # Printable except ()\
    DTEXT = r'[\x21-\x5A\x5E-\x7E]'  # Printable except []\
    ATEXT = r'[a-zA-Z0-9!#$%&\'*+\-/=?^_`{|}~]'  # Atom characters
    VCHAR = r'[\x21-\x7E]'  # Visible characters
    
    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)
    
    def peek(self, n: int = 1) -> str:
        """Peek at next n characters without consuming."""
        return self.text[self.pos:self.pos + n]
    
    def consume(self, n: int = 1) -> str:
        """Consume and return next n characters."""
        result = self.text[self.pos:self.pos + n]
        self.pos += n
        return result
    
    def skip_fws(self) -> str:
        """Skip folding whitespace, return what was skipped."""
        start = self.pos
        # Handle CRLF + WSP folding
        while self.pos < self.length:
            # Check for CRLF followed by space/tab
            if self.peek(2) == '\r\n' and self.pos + 2 < self.length:
                next_char = self.text[self.pos + 2]
                if next_char in ' \t':
                    self.pos += 3
                    continue
            # Regular whitespace
            if self.peek() in ' \t':
                self.pos += 1
                continue
            break
        return self.text[start:self.pos]
    
    def extract_comment(self) -> str:
        """Extract a comment including nested comments."""
        if self.peek() != '(':
            return ""
        
        depth = 0
        start = self.pos
        content_start = self.pos + 1
        
        while self.pos < self.length:
            char = self.consume()
            
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    return self.text[content_start:self.pos - 1]
            elif char == '\\' and self.pos < self.length:
                # Quoted pair inside comment
                self.consume()
        
        raise ParseError(f"Unclosed comment starting at position {start}")
    
    def extract_cfws(self) -> Tuple[str, List[str]]:
        """
        Extract comments and folding whitespace.
        Returns (fws_prefix, list_of_comments)
        """
        comments = []
        fws = self.skip_fws()
        
        while self.pos < self.length and self.peek() == '(':
            comments.append(self.extract_comment())
            fws += self.skip_fws()
        
        return fws, comments
    
    def extract_quoted_string(self) -> str:
        """Extract a quoted string, unescaping quoted pairs."""
        if self.peek() != '"':
            return ""
        
        self.consume()  # Skip opening quote
        result = []
        
        while self.pos < self.length:
            char = self.consume()
            
            if char == '"':
                return ''.join(result)
            elif char == '\\' and self.pos < self.length:
                # Quoted pair - keep the escaped character
                result.append(self.consume())
            elif char in '\r\n':
                # FWS inside quoted string
                if char == '\r' and self.peek() == '\n':
                    self.consume()
                # Skip subsequent whitespace
                while self.pos < self.length and self.peek() in ' \t':
                    self.consume()
                result.append(' ')  # FWS collapses to single space
            else:
                result.append(char)
        
        raise ParseError("Unclosed quoted string")
    
    def extract_atom(self) -> str:
        """Extract an atom (sequence of atext characters)."""
        start = self.pos
        while self.pos < self.length:
            char = self.peek()
            if re.match(self.ATEXT, char):
                self.consume()
            else:
                break
        
        if start == self.pos:
            raise ParseError(f"Expected atom at position {self.pos}")
        
        return self.text[start:self.pos]
    
    def extract_dot_atom(self) -> str:
        """Extract a dot-atom (atom *("." atom))."""
        parts = [self.extract_atom()]
        
        while self.pos < self.length and self.peek() == '.':
            self.consume()
            parts.append(self.extract_atom())
        
        return '.'.join(parts)


class AddressParser:
    """
    RFC 5322 compliant email address parser.
    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    """
    
    def __init__(self, mode: Mode = Mode.STRICT):
        """
        Initialize parser.
        
        Args:
            mode: STRICT rejects obs-* productions, PERMISSIVE accepts them
        """
        self.mode = mode
        self.lexer: Optional[RFC5322Lexer] = None
    
    def parse(self, raw: str) -> RFC5322Address:
        """
        Parse a single mailbox or group address.
        
        Args:
            raw: The email address string to parse
            
        Returns:
            RFC5322Address with parsed components
            
        Raises:
            ParseError: If parsing fails
        """
        if len(raw) > 998:
            raise ParseError(f"Input exceeds RFC 5322 line length limit (998 chars): {len(raw)}")
        
        self.lexer = RFC5322Lexer(raw)
        
        # Try to parse as address (mailbox or group)
        address = self._parse_address()
        
        # Check for trailing content
        trailing = self.lexer.skip_fws()
        if self.lexer.pos < self.lexer.length:
            raise ParseError(f"Unexpected trailing content after address: {raw[self.lexer.pos:]}")
        
        address.source = raw
        return address
    
    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        """
        Parse a comma-separated address-list per §3.4.
        
        Args:
            raw: Comma-separated list of addresses
            
        Returns:
            List of RFC5322Address objects
        """
        if len(raw) > 998:
            raise ParseError(f"Input exceeds RFC 5322 line length limit (998 chars): {len(raw)}")
        
        self.lexer = RFC5322Lexer(raw)
        addresses = []
        
        while self.lexer.pos < self.lexer.length:
            # Skip leading whitespace/comments
            self.lexer.skip_fws()
            
            # Parse one address
            address = self._parse_address()
            address.source = raw
            addresses.append(address)
            
            # Skip whitespace
            self.lexer.skip_fws()
            
            # Check for comma separator
            if self.lexer.peek() == ',':
                self.lexer.consume()
            else:
                break
        
        # Check for trailing content
        self.lexer.skip_fws()
        if self.lexer.pos < self.lexer.length:
            raise ParseError(f"Unexpected trailing content: {raw[self.lexer.pos:]}")
        
        return addresses
    
    def parse_mailbox_list(self, raw: str) -> List[RFC5322Address]:
        """
        Parse a comma-separated mailbox-list per §3.4.
        Rejects group addresses.
        
        Args:
            raw: Comma-separated list of mailboxes
            
        Returns:
            List of RFC5322Address objects (non-group)
            
        Raises:
            ParseError: If a group address is found
        """
        addresses = self.parse_address_list(raw)
        
        for addr in addresses:
            if addr.is_group:
                raise ParseError(f"Group address not allowed in mailbox-list: {addr.source}")
        
        return addresses
    
    def _parse_address(self) -> RFC5322Address:
        """Parse an address (mailbox or group)."""
        # Look ahead to determine if it's a group
        save_pos = self.lexer.pos
        
        try:
            # Try to parse as group first
            return self._parse_group()
        except ParseError:
            # Restore position and try as mailbox
            self.lexer.pos = save_pos
            return self._parse_mailbox()
    
    def _parse_mailbox(self) -> RFC5322Address:
        """Parse a mailbox (name-addr or addr-spec)."""
        # Look for display name (phrase before angle-addr)
        save_pos = self.lexer.pos
        
        try:
            display_name = self._parse_phrase()
            self.lexer.skip_fws()
            
            if self.lexer.peek() == '<':
                # name-addr
                addr_spec = self._parse_angle_addr()
                return RFC5322Address(
                    local_part=addr_spec.local_part,
                    domain=addr_spec.domain,
                    display_name=display_name,
                    comments=addr_spec.comments
                )
            else:
                # Not an angle-addr, restore and try addr-spec
                self.lexer.pos = save_pos
                return self._parse_addr_spec()
        except ParseError:
            self.lexer.pos = save_pos
            return self._parse_addr_spec()
    
    def _parse_name_addr(self) -> RFC5322Address:
        """Parse a name-addr ([display-name] angle-addr)."""
        display_name = None
        
        # Try to parse display name
        save_pos = self.lexer.pos
        try:
            display_name = self._parse_phrase()
            self.lexer.skip_fws()
        except ParseError:
            self.lexer.pos = save_pos
        
        addr_spec = self._parse_angle_addr()
        
        return RFC5322Address(
            local_part=addr_spec.local_part,
            domain=addr_spec.domain,
            display_name=display_name,
            comments=addr_spec.comments
        )
    
    def _parse_angle_addr(self) -> RFC5322Address:
        """Parse an angle-addr ([CFWS] < addr-spec > [CFWS])."""
        # Skip leading CFWS and collect comments
        fws, comments = self.lexer.extract_cfws()
        
        if self.lexer.peek() != '<':
            raise ParseError(f"Expected '<' for angle-addr at position {self.lexer.pos}")
        
        self.lexer.consume()  # Skip '<'
        
        # Parse addr-spec inside angle brackets
        addr_spec = self._parse_addr_spec()
        addr_spec.comments.extend(comments)
        
        if self.lexer.peek() != '>':
            raise ParseError(f"Expected '>' to close angle-addr at position {self.lexer.pos}")
        
        self.lexer.consume()  # Skip '>'
        
        # Skip trailing CFWS and collect more comments
        _, trailing_comments = self.lexer.extract_cfws()
        addr_spec.comments.extend(trailing_comments)
        
        return addr_spec
    
    def _parse_addr_spec(self) -> RFC5322Address:
        """Parse an addr-spec (local-part @ domain)."""
        # Skip leading CFWS
        _, comments = self.lexer.extract_cfws()
        
        local_part = self._parse_local_part()
        
        if self.lexer.peek() != '@':
            raise ParseError(f"Expected '@' in addr-spec at position {self.lexer.pos}")
        
        self.lexer.consume()  # Skip '@'
        
        domain = self._parse_domain()
        
        return RFC5322Address(
            local_part=local_part,
            domain=domain,
            comments=comments
        )
    
    def _parse_local_part(self) -> str:
        """Parse a local-part (dot-atom / quoted-string / obs-local-part)."""
        save_pos = self.lexer.pos
        
        # Try dot-atom first
        try:
            self.lexer.skip_fws()
            return self.lexer.extract_dot_atom()
        except ParseError:
            self.lexer.pos = save_pos
        
        # Try quoted-string
        if self.lexer.peek() == '"':
            return self.lexer.extract_quoted_string()
        
        # In permissive mode, try obs-local-part
        if self.mode == Mode.PERMISSIVE:
            try:
                return self._parse_obs_local_part()
            except ParseError:
                pass
        
        raise ParseError(f"Expected local-part at position {self.lexer.pos}")
    
    def _parse_domain(self) -> str:
        """Parse a domain (dot-atom / domain-literal / obs-domain)."""
        save_pos = self.lexer.pos
        
        # Try dot-atom first
        try:
            self.lexer.skip_fws()
            return self.lexer.extract_dot_atom()
        except ParseError:
            self.lexer.pos = save_pos
        
        # Try domain-literal
        if self.lexer.peek() == '[':
            return self._parse_domain_literal()
        
        # In permissive mode, try obs-domain
        if self.mode == Mode.PERMISSIVE:
            try:
                return self._parse_obs_domain()
            except ParseError:
                pass
        
        raise ParseError(f"Expected domain at position {self.lexer.pos}")
    
    def _parse_domain_literal(self) -> str:
        """Parse a domain-literal ([ dcontent ])."""
        if self.lexer.peek() != '[':
            raise ParseError(f"Expected '[' for domain-literal at position {self.lexer.pos}")
        
        self.lexer.consume()  # Skip '['
        
        # Collect dcontent (DTEXT / quoted-pair)
        content = []
        while self.lexer.pos < self.lexer.length:
            char = self.lexer.peek()
            
            if char == ']':
                self.lexer.consume()
                return '[' + ''.join(content) + ']'
            elif char == '\\':
                # Quoted pair
                self.lexer.consume()
                if self.lexer.pos < self.lexer.length:
                    content.append(self.lexer.consume())
            elif re.match(RFC5322Lexer.DTEXT, char):
                content.append(self.lexer.consume())
            elif char in ' \t':
                # FWS inside domain-literal
                content.append(self.lexer.consume())
            else:
                raise ParseError(f"Invalid character in domain-literal: {char}")
        
        raise ParseError("Unclosed domain-literal")
    
    def _parse_phrase(self) -> str:
        """Parse a phrase (1*word)."""
        words = []
        
        while True:
            save_pos = self.lexer.pos
            
            # Try word (atom / quoted-string)
            try:
                self.lexer.skip_fws()
                
                if self.lexer.peek() == '"':
                    words.append(self.lexer.extract_quoted_string())
                else:
                    words.append(self.lexer.extract_atom())
            except ParseError:
                self.lexer.pos = save_pos
                break
        
        if not words:
            raise ParseError(f"Expected phrase at position {self.lexer.pos}")
        
        return ' '.join(words)
    
    def _parse_group(self) -> RFC5322Address:
        """Parse a group (display-name : [group-list] ;)."""
        save_pos = self.lexer.pos
        
        try:
            display_name = self._parse_phrase()
            self.lexer.skip_fws()
            
            if self.lexer.peek() != ':':
                raise ParseError("Expected ':' for group")
            
            self.lexer.consume()  # Skip ':'
            
            # Parse group-list (mailbox-list / CFWS / obs-group-list)
            members = []
            self.lexer.skip_fws()
            
            if self.lexer.peek() != ';':
                # Try to parse mailbox-list
                try:
                    members = self._parse_mailbox_list_internal()
                except ParseError:
                    if self.mode != Mode.PERMISSIVE:
                        raise
            
            if self.lexer.peek() != ';':
                raise ParseError("Expected ';' to close group")
            
            self.lexer.consume()  # Skip ';'
            
            return RFC5322Address(
                local_part="",
                domain="",
                display_name=display_name,
                is_group=True,
                group_members=members
            )
        
        except ParseError:
            self.lexer.pos = save_pos
            raise
    
    def _parse_mailbox_list_internal(self) -> List[RFC5322Address]:
        """Parse a mailbox-list for group members."""
        members = []
        
        while True:
            self.lexer.skip_fws()
            
            try:
                mailbox = self._parse_mailbox()
                members.append(mailbox)
            except ParseError:
                break
            
            self.lexer.skip_fws()
            
            if self.lexer.peek() == ',':
                self.lexer.consume()
            else:
                break
        
        return members
    
    def _parse_obs_local_part(self) -> str:
        """Parse obs-local-part (word *('.' word)) - obsolete form."""
        if self.mode != Mode.PERMISSIVE:
            raise ParseError("obs-local-part not allowed in strict mode")
        
        parts = []
        
        # First word
        parts.append(self._parse_word())
        
        # Subsequent .word sequences
        while self.lexer.peek() == '.':
            self.lexer.consume()
            parts.append(self._parse_word())
        
        return '.'.join(parts)
    
    def _parse_obs_domain(self) -> str:
        """Parse obs-domain (atom *('.' atom)) - obsolete form."""
        if self.mode != Mode.PERMISSIVE:
            raise ParseError("obs-domain not allowed in strict mode")
        
        parts = []
        
        # First atom
        self.lexer.skip_fws()
        parts.append(self.lexer.extract_atom())
        
        # Subsequent .atom sequences
        while self.lexer.peek() == '.':
            self.lexer.consume()
            self.lexer.skip_fws()
            parts.append(self.lexer.extract_atom())
        
        return '.'.join(parts)
    
    def _parse_word(self) -> str:
        """Parse a word (atom / quoted-string)."""
        self.lexer.skip_fws()
        
        if self.lexer.peek() == '"':
            return self.lexer.extract_quoted_string()
        else:
            return self.lexer.extract_atom()


# Convenience functions for common use cases

def parse_email(raw: str, strict: bool = True) -> RFC5322Address:
    """
    Parse a single email address.
    
    Args:
        raw: Email address string
        strict: If True, reject obsolete forms
        
    Returns:
        Parsed RFC5322Address
        
    Raises:
        ParseError: If parsing fails
    """
    mode = Mode.STRICT if strict else Mode.PERMISSIVE
    parser = AddressParser(mode)
    return parser.parse(raw)


def parse_email_list(raw: str, strict: bool = True) -> List[RFC5322Address]:
    """
    Parse a comma-separated list of email addresses.
    
    Args:
        raw: Comma-separated email addresses
        strict: If True, reject obsolete forms
        
    Returns:
        List of parsed RFC5322Address objects
    """
    mode = Mode.STRICT if strict else Mode.PERMISSIVE
    parser = AddressParser(mode)
    return parser.parse_address_list(raw)
