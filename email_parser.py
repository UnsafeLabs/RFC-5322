import re
from typing import List, Optional, TypeAlias, TypeGuard

# Define RFC5322Address first as it's a self-referencing type
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: str | None
    local_part: str
    domain: str
    is_group: bool
    group_members: list['RFC5322Address']
    comments: list[str]
    source: str  # original unparsed input

    def __init__(self, display_name: str | None, local_part: str, domain: str,
                 is_group: bool = False, group_members: list['RFC5322Address'] | None = None,
                 comments: list[str] | None = None, source: str = ""):
        self.display_name = display_name
        self.local_part = local_part
        self.domain = domain
        self.is_group = is_group
        self.group_members = group_members if group_members is not None else []
        self.comments = comments if comments is not None else []
        self.source = source

    def __repr__(self) -> str:
        if self.is_group:
            members_repr = ", ".join(m.__repr__() for m in self.group_members)
            return f"Group(display='{self.display_name}', members=[{members_repr}], comments={self.comments})"
        return f"Mailbox(display='{self.display_name}', local='{self.local_part}', domain='{self.domain}', comments={self.comments})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RFC5322Address):
            return NotImplemented
        # Compare all relevant fields for equality. 'source' field is typically ignored.
        return (self.display_name == other.display_name and
                self.local_part == other.local_part and
                self.domain == other.domain and
                self.is_group == other.is_group and
                self.group_members == other.group_members and
                self.comments == other.comments)

class EmailParserError(Exception):
    """Custom exception for parser errors, indicating a syntax violation."""
    pass

class _ParserContext:
    """
    Internal class to hold the parsing state for a single raw input string.
    Manages current position, input string, strict mode, and collected comments
    for the current top-level address being parsed.
    """
    def __init__(self, raw_input: str, strict: bool):
        self.s = raw_input
        self.pos = 0
        self.length = len(raw_input)
        self.strict = strict
        self.collected_comments: list[str] = [] # Accumulates comments for the current address being built

    def _peek(self, length: int = 1) -> str:
        """Peek at the next characters without advancing the pointer."""
        if self.pos + length <= self.length:
            return self.s[self.pos : self.pos + length]
        return ''

    def _current_char(self) -> str:
        """Return the character at the current position."""
        return self.s[self.pos] if self.pos < self.length else ''

    def _advance(self, length: int):
        """Advance the internal pointer by the given length."""
        self.pos += length

    def _match_regex(self, pattern: str, advance: bool = True) -> Optional[re.Match]:
        """
        Attempts to match a regex pattern from the current position.
        If successful, advances the pointer by the match's length if `advance` is True.
        """
        match = re.match(pattern, self.s, self.pos) # Use `pos` for start of match
        if match and advance:
            self.pos += match.end() - match.start() # Advance by matched length
        return match

    def _parse_fws(self) -> bool:
        """
        Parses Folding White Space (FWS) according to RFC 5322 §3.2.2.
        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        obs-FWS = 1*WSP *(CRLF 1*WSP)
        Returns True if FWS was consumed, False otherwise.
        """
        initial_pos = self.pos

        # Try matching standard FWS: ([*WSP CRLF] 1*WSP)
        match = self._match_regex(r'(?:[ \t]*\r?\n)?[ \t]+', advance=True)
        if match:
            return True

        if not self.strict:
            # Try matching obs-FWS: 1*WSP *(CRLF 1*WSP)
            match = self._match_regex(r'[ \t]+(?:\r?\n[ \t]+)*', advance=True)
            if match:
                return True
        
        self.pos = initial_pos # No FWS found
        return False

    def _parse_comment(self) -> Optional[str]:
        """
        Parses a comment.
        comment = "(" *([FWS] ccontent) [FWS] ")"
        ccontent = ctext / quoted-pair / comment
        Returns the comment string (excluding parentheses) if successful.
        Adds comment to self.collected_comments.
        """
        initial_pos = self.pos
        if self._current_char() != '(':
            return None

        self._advance(1) # Consume '('
        
        comment_parts: list[str] = []
        nesting_level = 1
        
        while nesting_level > 0 and self.pos < self.length:
            # FWS can appear within comments, but is generally ignored for the comment's content itself.
            self._parse_fws() 

            char = self._current_char()

            if char == '(': # Nested comment
                nested_comment_start_pos = self.pos
                nested_comment = self._parse_comment() # Recursive call: this adds to self.collected_comments
                if nested_comment is None:
                    self.pos = initial_pos
                    raise EmailParserError(f"Malformed nested comment starting at position {nested_comment_start_pos}")
                comment_parts.append(f"({nested_comment})") # Store nested comment fully, including outer parens
                continue

            elif char == ')':
                self._advance(1) # Consume ')'
                nesting_level -= 1
                if nesting_level == 0:
                    break # Outermost comment closed
                else: # Inner comment closed, append ')' to content
                    comment_parts.append(char)

            elif char == '\\': # quoted-pair (incl. obs-qp)
                qp_start_pos = self.pos
                qp_char = self._parse_quoted_pair()
                if qp_char is None:
                    self.pos = initial_pos
                    raise EmailParserError(f"Malformed quoted-pair in comment at position {qp_start_pos}")
                comment_parts.append('\\') # Preserve the backslash for comment content
                comment_parts.append(qp_char)
            
            # ctext = %d33-39 / %d42-91 / %d93-126 / obs-ctext
            # obs-ctext = %d0 / obs-NO-WS-CTL / VCHAR
            # In essence, any character except '(', ')', '\', NUL, CR, LF for standard ctext.
            # obs-ctext relaxes this, allowing NUL and control characters.
            elif 0 <= ord(char) <= 127 and char not in '()\\\r\n':
                comment_parts.append(char)
                self._advance(1)
            elif not self.strict and (0 <= ord(char) <= 127): # obs-ctext allows any US-ASCII (except for '()\\')
                comment_parts.append(char)
                self._advance(1)
            else:
                self.pos = initial_pos
                raise EmailParserError(f"Invalid character in comment at position {self.pos}: '{char}' (ASCII: {ord(char)})")
        
        if nesting_level > 0:
            self.pos = initial_pos
            raise EmailParserError("Unclosed comment")
        
        comment_str = "".join(comment_parts)
        self.collected_comments.append(comment_str) # Add to the list of collected comments for the current address
        return comment_str

    def _skip_cfws_and_collect(self) -> None:
        """
        Handles Folding White Space (FWS) and Comments (CFWS) according to RFC 5322 §3.2.3.
        CFWS = (1*FWS comment) / (comment 1*FWS) / comment / FWS
        Iteratively consumes FWS and comments. Collected comments are stored in self.collected_comments.
        """
        while True:
            initial_pos = self.pos
            
            fws_consumed = self._parse_fws()
            comment_parsed = self._parse_comment() # This will add to self.collected_comments if successful.

            if fws_consumed or comment_parsed is not None:
                # Continue loop to find more FWS or comments
                pass
            else:
                break # No CFWS found, exit loop

    def _parse_quoted_pair(self) -> Optional[str]:
        """
        Parses a quoted-pair (e.g., '\char').
        quoted-pair = ("\" (VCHAR / WSP)) / obs-qp
        obs-qp = "\" (%d0-127) ; any US-ASCII character
        This implementation covers both standard and obsolete quoted-pair by allowing any US-ASCII.
        """
        if self._current_char() == '\\':
            if self.pos + 1 < self.length:
                char = self.s[self.pos + 1]
                if 0 <= ord(char) <= 127: # Any US-ASCII character is allowed (covers VCHAR, WSP, and obs-qp)
                    self._advance(2)
                    return char
            raise EmailParserError(f"Invalid quoted-pair (missing character after backslash) at position {self.pos}")
        return None

    def _parse_qcontent(self) -> Optional[str]:
        """
        Parses qtext or quoted-pair for quoted-string.
        qtext = %d33 / %d35-91 / %d93-126 / obs-qtext
        obs-qtext = %d0 / obs-NO-WS-CTL / VCHAR
        This covers any US-ASCII character except DQUOTE ("), backslash (\), CR (13), LF (10).
        FWS within quoted-string is handled by _parse_quoted_string.
        """
        # quoted-pair has precedence
        qp = self._parse_quoted_pair()
        if qp is not None:
            return qp

        char = self._current_char()
        if not char: return None

        # qtext characters (excluding DQUOTE, BACKSLASH, CR, LF)
        if char not in ['"', '\\', '\r', '\n'] and 0 <= ord(char) <= 127:
            self._advance(1)
            return char
        
        return None

    def _parse_quoted_string(self) -> Optional[str]:
        """
        Parses a quoted-string.
        quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot for backtracking

        self._skip_cfws_and_collect() # [CFWS] before quoted-string

        if self._current_char() == '"':
            self._advance(1) # Consume DQUOTE
            parts: list[str] = []
            while self.pos < self.length:
                self._parse_fws() # *([FWS] qcontent) - consume FWS within quotes
                
                if self._current_char() == '"':
                    self._advance(1) # Consume closing DQUOTE
                    self._skip_cfws_and_collect() # [CFWS] after quoted-string
                    return "".join(parts)

                qcontent = self._parse_qcontent()
                if qcontent is not None:
                    parts.append(qcontent)
                else:
                    self.pos = initial_pos
                    self.collected_comments = initial_comments_state
                    raise EmailParserError(f"Invalid character in quoted-string at position {self.pos}: '{self._current_char()}' (ASCII: {ord(self._current_char()) if self._current_char() else 'N/A'})")
            
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            raise EmailParserError("Unclosed quoted-string")
        
        self.pos = initial_pos # Backtrack if no quoted string was found
        self.collected_comments = initial_comments_state # Restore comments
        return None

    def _parse_atext(self) -> Optional[str]:
        """
        Parses atext (single character).
        atext = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*"
                / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
        """
        char = self._current_char()
        # This regex matches the full set of characters for 'atext'.
        if re.match(r'[a-zA-Z0-9!#$%&\'*+\-/=?^_`{|}~]', char):
            self._advance(1)
            return char
        return None

    def _parse_atom(self) -> Optional[str]:
        """
        Parses an atom (1*atext).
        """
        initial_pos = self.pos
        atom_parts: list[str] = []
        while True:
            atext = self._parse_atext()
            if atext:
                atom_parts.append(atext)
            else:
                break
        
        if not atom_parts:
            self.pos = initial_pos
            return None
        return "".join(atom_parts)
    
    def _parse_dot_atom_text(self) -> Optional[str]:
        """
        Parses dot-atom-text (1*atext *("." 1*atext)).
        Disallows leading, trailing, or consecutive dots.
        """
        initial_pos = self.pos
        parts: list[str] = []
        
        first_atext_group = self._parse_atom()
        if not first_atext_group:
            self.pos = initial_pos
            return None
        parts.append(first_atext_group)

        while self._current_char() == '.':
            self._advance(1) # Consume '.'
            parts.append('.')
            
            next_atext_group = self._parse_atom()
            if not next_atext_group:
                self.pos = initial_pos # Invalid dot-atom-text (e.g., 'a..b' or 'a.')
                raise EmailParserError(f"Invalid dot-atom-text: dot followed by no atext at position {self.pos-1}")
            parts.append(next_atext_group)
        
        return "".join(parts)

    def _parse_dot_atom(self) -> Optional[str]:
        """
        Parses a dot-atom = [CFWS] dot-atom-text [CFWS].
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)

        self._skip_cfws_and_collect() # [CFWS] before dot-atom-text
        
        dot_atom_text = self._parse_dot_atom_text()
        
        if not dot_atom_text:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        
        self._skip_cfws_and_collect() # [CFWS] after dot-atom-text
        return dot_atom_text

    def _parse_dcontent(self) -> Optional[str]:
        """
        Parses dtext or quoted-pair for domain-literal.
        dtext = VCHAR / WSP / obs-dtext ; Any character except "[", "]", or "\"
        obs-dtext = %d0 / obs-NO-WS-CTL / VCHAR
        This covers any US-ASCII character except '[', ']', '\', CR, LF.
        FWS within domain-literal is handled by _parse_domain_literal.
        """
        qp = self._parse_quoted_pair()
        if qp is not None:
            return qp

        char = self._current_char()
        if not char: return None

        # dtext characters (excluding '[', ']', '\', CR, LF)
        if char not in ['[', ']', '\\', '\r', '\n'] and 0 <= ord(char) <= 127:
            self._advance(1)
            return char
        
        return None

    def _parse_domain_literal(self) -> Optional[str]:
        """
        Parses a domain-literal.
        domain-literal = [CFWS] "[" *([FWS] dcontent) [FWS] "]"
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)

        self._skip_cfws_and_collect() # [CFWS] before domain-literal

        if self._current_char() == '[':
            self._advance(1) # Consume '['
            parts: list[str] = []
            while self.pos < self.length:
                self._parse_fws() # *([FWS] dcontent) - consume FWS within literal

                if self._current_char() == ']':
                    self._advance(1) # Consume ']'
                    self._skip_cfws_and_collect() # [CFWS] after domain-literal
                    return "".join(parts)

                dcontent = self._parse_dcontent()
                if dcontent is not None:
                    parts.append(dcontent)
                else:
                    self.pos = initial_pos
                    self.collected_comments = initial_comments_state
                    raise EmailParserError(f"Invalid character in domain-literal at position {self.pos}: '{self._current_char()}' (ASCII: {ord(self._current_char()) if self._current_char() else 'N/A'})")
            
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            raise EmailParserError("Unclosed domain-literal")
        
        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

    def _parse_word(self) -> Optional[str]:
        """
        Parses a word (atom / quoted-string).
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)

        # Quoted-string takes precedence as it has a distinct start token (")
        quoted_string = self._parse_quoted_string()
        if quoted_string is not None:
            return quoted_string
        
        # Atom has no distinct start token
        atom = self._parse_atom()
        if atom is not None:
            return atom

        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None
    
    def _parse_obs_sequence_with_dots(self, part_parser_func) -> Optional[str]:
        """
        Helper for obs-local-part and obs-domain which allow sequence of words/atoms separated by dots,
        potentially including leading/trailing, or consecutive dots.
        part_parser_func should be _parse_atom or _parse_word.
        """
        if self.strict:
            return None # Obsolete forms not allowed in strict mode
        
        initial_pos = self.pos
        parts: list[str] = []
        
        # Allow leading dot (e.g., .local@domain)
        if self._current_char() == '.':
            self._advance(1)
            parts.append('.')
        
        # First part (required after optional leading dot)
        part = part_parser_func()
        if part is None:
             if parts: # If we only had a leading dot, but no part after it, it's not a complete sequence.
                 self.pos = initial_pos
                 return None
             return None # No part at all, cannot be obs-sequence
        parts.append(part)

        while self.pos < self.length:
            if self._current_char() == '.':
                self._advance(1)
                parts.append('.')
                
                # After a dot, an atom/word is expected per RFC ABNF obs-domain/obs-local-part.
                # However, common interpretations and some RFC examples (implicitly) allow consecutive/trailing dots.
                # This logic is permissive for dots in obsolete mode.
                next_part = part_parser_func()
                if next_part is not None:
                    parts.append(next_part)
                # If next_part is None, and we just consumed a '.', it's a consecutive/trailing dot,
                # which is generally accepted in obsolete forms. Loop continues to look for more dots/parts.
            else:
                break 
        
        if not parts: # Should not happen if first part was successfully parsed.
            self.pos = initial_pos
            return None
        
        return "".join(parts)


    def _parse_local_part(self) -> Optional[str]:
        """
        Parses a local-part (dot-atom / quoted-string / obs-local-part).
        obs-local-part = word *("." word)
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)
        
        # Priority: quoted-string (distinct start token), then dot-atom (standard), then obs-local-part
        # CFWS around the local-part is handled by _parse_addr_spec.

        quoted_string = self._parse_quoted_string()
        if quoted_string is not None:
            return quoted_string
        
        dot_atom = self._parse_dot_atom()
        if dot_atom is not None:
            return dot_atom
        
        # Obsolete local-part is only allowed if not in strict mode
        if not self.strict:
            obs_local = self._parse_obs_sequence_with_dots(self._parse_word)
            if obs_local is not None:
                return obs_local
        
        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

    def _parse_domain(self) -> Optional[str]:
        """
        Parses a domain (dot-atom / domain-literal / obs-domain).
        obs-domain = atom *("." atom)
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)

        # Priority: domain-literal (distinct start token), then dot-atom (standard), then obs-domain
        # CFWS around the domain is handled by _parse_addr_spec.
        
        domain_literal = self._parse_domain_literal()
        if domain_literal is not None:
            return domain_literal

        dot_atom = self._parse_dot_atom()
        if dot_atom is not None:
            return dot_atom
        
        # Obsolete domain is only allowed if not in strict mode
        if not self.strict:
            obs_domain = self._parse_obs_sequence_with_dots(self._parse_atom)
            if obs_domain is not None:
                return obs_domain
        
        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

    def _parse_addr_spec(self) -> Optional[RFC5322Address]:
        """Parses an addr-spec = local-part "@" domain."""
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot collected comments for backtracking

        self._skip_cfws_and_collect() # CFWS before local-part
        
        local_part = self._parse_local_part()
        if local_part is None:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        
        self._skip_cfws_and_collect() # CFWS around '@'

        if self._current_char() != '@':
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        self._advance(1) # Consume '@'

        self._skip_cfws_and_collect() # CFWS around domain
        
        domain = self._parse_domain()
        if domain is None:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        
        self._skip_cfws_and_collect() # CFWS after domain

        # Comments are accumulated in self.collected_comments throughout the process.
        # Now, create the RFC5322Address object with the current accumulated comments.
        final_comments = list(self.collected_comments) # Copy the accumulated comments
        self.collected_comments = [] # Clear comments for next parsing segment/address

        return RFC5322Address(
            display_name=None,
            local_part=local_part,
            domain=domain,
            comments=final_comments
        )

    def _parse_phrase(self) -> Optional[str]:
        """
        Parses a phrase (1*word / obs-phrase).
        phrase = 1*word
        obs-phrase = word *(word / "." / CFWS)
        For display-name, we join words and collapse spaces/comments.
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)
        
        words: list[str] = []
        
        # Phrase can start with CFWS or word. We skip CFWS, then parse words.
        # CFWS can also appear between words.
        while True:
            self._skip_cfws_and_collect() 
            
            word = self._parse_word()
            if word:
                words.append(word)
            elif not self.strict and self._current_char() == '.': # obs-phrase allows '.' as a word separator
                self._advance(1)
                words.append('.')
            else:
                break
        
        if not words:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        
        # Join words with single space for display-name.
        return " ".join(words).strip()

    def _parse_obs_route(self) -> List[str]:
        """
        Parses obs-route = "@" domain * ("," "@" domain) ":"
        This is typically ignored by modern email systems but must be parsable.
        """
        if self.strict:
            return [] # obs-route not allowed in strict mode

        route_domains: List[str] = []
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot for backtracking

        if self._current_char() != '@':
            return [] # Not starting with an obsolete route

        while True:
            self._skip_cfws_and_collect()
            if self._current_char() == '@':
                self._advance(1) # Consume '@'
                self._skip_cfws_and_collect()
                domain = self._parse_domain() # Use the domain parser
                if domain:
                    route_domains.append(domain)
                    self._skip_cfws_and_collect()
                    # Check for continuation or end of route
                    if self._current_char() == ',':
                        self._advance(1) # Consume ',' and expect another "@" domain
                        continue
                    elif self._current_char() == ':':
                        self._advance(1) # Consume ':' end of route
                        return route_domains
                    else: # Malformed route
                        self.pos = initial_pos
                        self.collected_comments = initial_comments_state
                        raise EmailParserError(f"Malformed obs-route: expected ',' or ':' at {self.pos}")
                else: # Malformed route
                    self.pos = initial_pos
                    self.collected_comments = initial_comments_state
                    raise EmailParserError(f"Malformed obs-route: expected domain after '@' at {self.pos}")
            else: # Not '@'
                break

        self.pos = initial_pos # If we get here without a full route (e.g., just "@"), backtrack.
        self.collected_comments = initial_comments_state
        return []

    def _parse_angle_addr(self) -> Optional[RFC5322Address]:
        """
        Parses angle-addr = [CFWS] "<" [obs-route] addr-spec ">" [CFWS].
        """
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot for backtracking

        self._skip_cfws_and_collect() # [CFWS] before '<'

        if self._current_char() == '<':
            self._advance(1) # Consume '<'
            self._skip_cfws_and_collect()
            
            # Attempt to parse obs-route. It manages its own backtracking for internal failures.
            route_domains = self._parse_obs_route() # Result is discarded per RFC5322Address structure.

            addr_spec_obj = self._parse_addr_spec() # _parse_addr_spec handles its own comments collection
            if addr_spec_obj is None:
                self.pos = initial_pos
                self.collected_comments = initial_comments_state
                raise EmailParserError("Invalid addr-spec inside angle brackets")

            self._skip_cfws_and_collect()
            if self._current_char() == '>':
                self._advance(1) # Consume '>'
                self._skip_cfws_and_collect() # [CFWS] after '>'

                # _parse_addr_spec would have cleared self.collected_comments after its parse.
                # So here, self.collected_comments contains only comments accumulated directly around
                # the angle-address structure, which should be added to the addr_spec_obj's comments.
                addr_spec_obj.comments.extend(initial_comments_state + self.collected_comments)
                self.collected_comments = [] # Clear comments for next parsing segment

                return addr_spec_obj
            else:
                self.pos = initial_pos
                self.collected_comments = initial_comments_state
                raise EmailParserError("Unclosed angle bracket in angle-addr")
        
        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

    def _parse_name_addr(self) -> Optional[RFC5322Address]:
        """Parses name-addr = [display-name] angle-addr."""
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot for backtracking

        # Attempt to parse display-name (phrase).
        # This will collect comments into self.collected_comments.
        display_name = self._parse_phrase() 
        
        # After phrase, more CFWS might exist before angle-addr.
        self._skip_cfws_and_collect() 
        
        angle_addr_obj = self._parse_angle_addr()

        if angle_addr_obj is None:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state # Restore comments state on failure
            return None
        
        # If angle_addr was successfully parsed, we have a name-addr.
        angle_addr_obj.display_name = display_name # Set display_name
        
        # _parse_angle_addr already includes comments accumulated during _parse_phrase.
        # Add any comments that were present before this name-addr started parsing.
        angle_addr_obj.comments.extend(initial_comments_state)
        self.collected_comments = [] # Clear for next parsing segment

        return angle_addr_obj

    def _parse_mailbox(self) -> Optional[RFC5322Address]:
        """Parses mailbox = name-addr / addr-spec."""
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)
        
        # Try name-addr first, as its pattern (optional display-name then angle-addr) is more specific
        name_addr = self._parse_name_addr()
        if name_addr is not None:
            return name_addr
        
        # If name-addr failed, try addr-spec directly.
        # Reset position and comments because _parse_name_addr might have advanced/collected comments
        # before failing to find the angle_addr.
        self.pos = initial_pos
        self.collected_comments = initial_comments_state 
        
        addr_spec = self._parse_addr_spec()
        if addr_spec is not None:
            return addr_spec
        
        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

    def _parse_mailbox_list(self) -> List[RFC5322Address]:
        """Parses a list of mailboxes, typically used in groups, per §3.4."""
        mailboxes: List[RFC5322Address] = []

        while self.pos < self.length:
            mailbox_start_pos = self.pos
            
            # Clear comments specific to this _parse_mailbox_list call for each individual mailbox
            # These will be accumulated by _parse_mailbox into the mailbox_obj.comments.
            # Then the parser_context.collected_comments will be reset for the next mailbox in the list.
            
            self._skip_cfws_and_collect() # CFWS before the current mailbox
            
            mailbox_obj = self._parse_mailbox()

            if mailbox_obj:
                mailbox_obj.source = self.s[mailbox_start_pos:self.pos].strip()
                mailboxes.append(mailbox_obj)
                
                # Check for comma and more mailboxes
                self._skip_cfws_and_collect() # CFWS after mailbox, before comma
                if self._current_char() == ',':
                    self._advance(1) # Consume comma
                    self._skip_cfws_and_collect() # CFWS after comma
                else:
                    break # End of list or next char is not a comma
            else:
                # If _parse_mailbox returns None, it means no valid mailbox was found at the current position.
                # If there's still non-whitespace content, it's a parsing error.
                if self.s[self.pos:].strip():
                     raise EmailParserError(f"Malformed mailbox in list: '{self.s[self.pos:]}' at position {self.pos}")
                break # No more mailboxes and no unparsed content, break
        return mailboxes
    
    def _parse_group(self) -> Optional[RFC5322Address]:
        """Parses a group = display-name ":" [mailbox-list] ";" [CFWS]."""
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments) # Snapshot for backtracking

        group_start_pos = self.pos # For source field
        
        self._skip_cfws_and_collect() # CFWS before display-name
        display_name = self._parse_phrase() # _parse_phrase collects its own comments
        if display_name is None:
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        
        self._skip_cfws_and_collect() # CFWS before ':'
        if self._current_char() != ':':
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            return None
        self._advance(1) # Consume ':'

        self._skip_cfws_and_collect() # CFWS before mailbox-list
        mailbox_list = self._parse_mailbox_list() # mailbox-list is optional, handles its own comments for members

        self._skip_cfws_and_collect() # CFWS before ';'
        if self._current_char() != ';':
            self.pos = initial_pos
            self.collected_comments = initial_comments_state
            raise EmailParserError(f"Group address '{display_name}' missing closing semicolon at position {self.pos}")
        self._advance(1) # Consume ';'
        
        self._skip_cfws_and_collect() # CFWS after ';'

        # The self.collected_comments now contains all comments accumulated throughout the group parsing,
        # excluding those collected and attached to individual mailbox members by _parse_mailbox_list.
        final_comments = list(initial_comments_state + self.collected_comments)
        self.collected_comments = [] # Clear comments for next parsing segment/address

        return RFC5322Address(
            display_name=display_name,
            local_part="", # Group addresses don't have local_part/domain directly
            domain="",
            is_group=True,
            group_members=mailbox_list,
            comments=final_comments,
            source=self.s[group_start_pos:self.pos]
        )

    def _parse_address(self) -> Optional[RFC5322Address]:
        """Parses an address = mailbox / group."""
        initial_pos = self.pos
        initial_comments_state = list(self.collected_comments)

        # Try parsing group first, as its pattern (display-name ":" ...) is more specific
        group = self._parse_group()
        if group is not None:
            return group
        
        # If group failed, reset position and collected comments before trying mailbox
        self.pos = initial_pos
        self.collected_comments = initial_comments_state

        mailbox = self._parse_mailbox()
        if mailbox is not None:
            return mailbox

        self.pos = initial_pos
        self.collected_comments = initial_comments_state
        return None

# Public AddressParser class
class AddressParser:
    """
    RFC 5322 compliant email address parser.
    
    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    """
    
    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, reject obs-* productions. 
                    If False, accept obsolete forms per §4.4.
        """
        self.strict_mode = strict
    
    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        parser_context = _ParserContext(raw, self.strict_mode)
        
        try:
            parsed_address = parser_context._parse_address()
            
            if parsed_address is None:
                raise EmailParserError(f"Could not parse '{raw}' as a valid RFC 5322 address.")
            
            # After parsing, ensure no unparsed characters remain (or only CFWS)
            parser_context._skip_cfws_and_collect()
            if parser_context.pos < parser_context.length:
                raise EmailParserError(f"Unexpected characters after parsing address: '{raw[parser_context.pos:]}' at position {parser_context.pos}")
            
            parsed_address.source = raw # Set source for the top-level address
            
            # Comments should already be attached to the parsed_address object or its members
            # via the _ParserContext.collected_comments mechanism which gets transferred at _parse_address/_parse_group end.
            # If any comments remain in parser_context.collected_comments at this point,
            # they were accumulated *after* the address object was finalized, likely due to post-address CFWS.
            # These should be added to the main address object's comments.
            if parser_context.collected_comments:
                 parsed_address.comments.extend(parser_context.collected_comments)

            return parsed_address
        except EmailParserError as e:
            raise e
        except Exception as e:
            raise EmailParserError(f"An unexpected error occurred during parsing: {e}") from e
    
    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        parser_context = _ParserContext(raw, self.strict_mode)
        addresses: list[RFC5322Address] = []

        while parser_context.pos < parser_context.length:
            address_start_pos = parser_context.pos
            
            # Clear comments for each individual address within the list
            # The comments accumulated by parser_context._parse_address will be transferred to address_obj.comments.
            parser_context.collected_comments = []

            parser_context._skip_cfws_and_collect() # CFWS before the current address
            address_obj = parser_context._parse_address()
            
            if address_obj:
                address_obj.source = raw[address_start_pos:parser_context.pos].strip()
                addresses.append(address_obj)
                
                # Check for comma and more addresses
                parser_context._skip_cfws_and_collect()
                if parser_context._current_char() == ',':
                    parser_context._advance(1) # Consume comma
                    parser_context._skip_cfws_and_collect() # CFWS after comma
                    if parser_context.pos == parser_context.length: # Trailing comma
                        if self.strict_mode:
                            raise EmailParserError("Trailing comma in address-list (strict mode)")
                        # In permissive mode, trailing comma is accepted.
                else:
                    break # End of list or next char is not a comma
            else:
                # If _parse_address returns None, it means no valid address was found at the current position.
                # If there's still non-whitespace content, it's a parsing error.
                if raw[parser_context.pos:].strip(): # Check for meaningful content
                     raise EmailParserError(f"Malformed address in list: '{raw[parser_context.pos:]}' at position {parser_context.pos}")
                break # No more addresses and no unparsed content, break

        parser_context._skip_cfws_and_collect() # Final check for residual CFWS at the end of the list
        if parser_context.pos < parser_context.length:
            raise EmailParserError(f"Unexpected characters after parsing address list: '{raw[parser_context.pos:]}' at position {parser_context.pos}")

        return addresses
    
    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        parser_context = _ParserContext(raw, self.strict_mode)
        mailboxes: list[RFC5322Address] = []

        while parser_context.pos < parser_context.length:
            mailbox_start_pos = parser_context.pos
            
            # Clear comments for each individual mailbox within the list
            parser_context.collected_comments = []

            parser_context._skip_cfws_and_collect() # CFWS before the current mailbox
            mailbox_obj = parser_context._parse_mailbox()
            
            if mailbox_obj:
                mailbox_obj.source = raw[mailbox_start_pos:parser_context.pos].strip()
                mailboxes.append(mailbox_obj)
                
                # Check for comma and more mailboxes
                parser_context._skip_cfws_and_collect()
                if parser_context._current_char() == ',':
                    parser_context._advance(1) # Consume comma
                    parser_context._skip_cfws_and_collect() # CFWS after comma
                    if parser_context.pos == parser_context.length: # Trailing comma
                        if self.strict_mode:
                            raise EmailParserError("Trailing comma in mailbox-list (strict mode)")
                        # In permissive mode, trailing comma is accepted.
                else:
                    break # End of list or next char is not a comma
            else:
                if raw[parser_context.pos:].strip(): # Check for meaningful content
                     raise EmailParserError(f"Malformed mailbox in list: '{raw[parser_context.pos:]}' at position {parser_context.pos}")
                break # No more mailboxes and no unparsed content, break

        parser_context._skip_cfws_and_collect() # Final check for residual CFWS at the end of the list
        if parser_context.pos < parser_context.length:
            raise EmailParserError(f"Unexpected characters after parsing mailbox list: '{raw[parser_context.pos:]}' at position {parser_context.pos}")
        
        return mailboxes