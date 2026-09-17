import re

class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: str | None
    local_part: str
    domain: str
    is_group: bool
    group_members: list['RFC5322Address']
    comments: list[str]
    source: str  # original unparsed input

    def __init__(
        self,
        display_name: str | None = None,
        local_part: str = "",
        domain: str = "",
        is_group: bool = False,
        group_members: list['RFC5322Address'] | None = None,
        comments: list[str] | None = None,
        source: str = ""
    ):
        self.display_name = display_name
        self.local_part = local_part
        self.domain = domain
        self.is_group = is_group
        self.group_members = group_members if group_members is not None else []
        self.comments = comments if comments is not None else []
        self.source = source

    def __repr__(self) -> str:
        if self.is_group:
            return f"Group({self.display_name!r}, members={self.group_members!r}, comments={self.comments!r})"
        return f"Mailbox({self.display_name!r}, {self.local_part!r}@{self.domain!r}, comments={self.comments!r})"


class ParserState:
    def __init__(self, raw: str, strict: bool):
        self.raw = raw
        self.strict = strict
        self.pos = 0
        self.length = len(raw)

    def peek_char(self) -> str:
        if self.pos >= self.length:
            return ''
        return self.raw[self.pos]

    def consume_char(self) -> str:
        if self.pos >= self.length:
            return ''
        c = self.raw[self.pos]
        self.pos += 1
        return c

    def match_char(self, expected: str) -> bool:
        if self.peek_char() == expected:
            self.consume_char()
            return True
        return False

    def parse_fws(self) -> str | None:
        if self.pos >= self.length:
            return None
        
        if self.strict:
            pattern = re.compile(r'(?:[ \t]*\r\n)?[ \t]+')
        else:
            pattern = re.compile(r'(?:(?:[ \t]*\r\n)?[ \t]+|[ \t]+(?:\r\n[ \t]+)*)')
            
        match = pattern.match(self.raw, self.pos)
        if match:
            val = match.group(0)
            self.pos += len(val)
            return val
        return None

    def is_ctext(self, c: str) -> bool:
        if not c:
            return False
        o = ord(c)
        if (33 <= o <= 39) or (42 <= o <= 91) or (93 <= o <= 126):
            return True
        if not self.strict:
            if (1 <= o <= 8) or (o == 11) or (o == 12) or (14 <= o <= 31) or (o == 127):
                return True
        return False

    def is_qtext(self, c: str) -> bool:
        if not c:
            return False
        o = ord(c)
        if o == 33 or (35 <= o <= 91) or (93 <= o <= 126):
            return True
        if not self.strict:
            if (1 <= o <= 8) or (o == 11) or (o == 12) or (14 <= o <= 31) or (o == 127):
                return True
        return False

    def is_dtext(self, c: str) -> bool:
        if not c:
            return False
        o = ord(c)
        if (33 <= o <= 90) or (94 <= o <= 126):
            return True
        if not self.strict:
            if (1 <= o <= 8) or (o == 11) or (o == 12) or (14 <= o <= 31) or (o == 127):
                return True
        return False

    def is_atext(self, c: str) -> bool:
        if not c:
            return False
        o = ord(c)
        if (65 <= o <= 90) or (97 <= o <= 122) or (48 <= o <= 57):
             return True
        return c in "!#$%&'*+-/=?^_`{|}~"

    def parse_quoted_pair(self) -> str:
        if not self.match_char('\\'):
            raise ValueError("Expected '\\'")
        c = self.peek_char()
        if c == '':
            raise ValueError("Unterminated quoted-pair")
        o = ord(c)
        if self.strict:
            if (33 <= o <= 126) or c in (' ', '\t'):
                self.consume_char()
                return '\\' + c
            else:
                raise ValueError(f"Invalid character in strict quoted-pair: {c!r}")
        else:
            self.consume_char()
            return '\\' + c

    def parse_comment(self) -> str:
        if not self.match_char('('):
            raise ValueError("Expected '('")
        
        content_parts = []
        while True:
            fws = self.parse_fws()
            if fws:
                content_parts.append(fws.replace('\r\n', ''))
            
            c = self.peek_char()
            if c == ')':
                self.consume_char()
                break
            elif c == '(':
                nested_val = self.parse_comment()
                content_parts.append('(' + nested_val + ')')
            elif c == '\\':
                qp = self.parse_quoted_pair()
                content_parts.append(qp[1:])
            elif c == '':
                raise ValueError("Unterminated comment")
            else:
                if self.is_ctext(c):
                    content_parts.append(c)
                    self.consume_char()
                else:
                    raise ValueError(f"Invalid character in comment: {c!r}")
                    
        return "".join(content_parts)

    def parse_cfws_into(self, comments_list: list[str]):
        while True:
            self.parse_fws()
            if self.peek_char() == '(':
                comments_list.append(self.parse_comment())
            else:
                break

    def parse_quoted_string_core(self) -> str:
        if not self.match_char('"'):
            raise ValueError("Expected DQUOTE")
        
        content_parts = []
        while True:
            fws = self.parse_fws()
            if fws:
                content_parts.append(fws.replace('\r\n', ''))
            
            c = self.peek_char()
            if c == '"':
                self.consume_char()
                break
            elif c == '\\':
                qp = self.parse_quoted_pair()
                content_parts.append(qp[1:])
            elif c == '':
                raise ValueError("Unterminated quoted-string")
            else:
                if self.is_qtext(c):
                    content_parts.append(c)
                    self.consume_char()
                else:
                    raise ValueError(f"Invalid character in quoted-string: {c!r}")
                    
        return "".join(content_parts)

    def parse_atom_core(self) -> str:
        start = self.pos
        while True:
            c = self.peek_char()
            if self.is_atext(c):
                self.consume_char()
            else:
                break
        if self.pos == start:
            raise ValueError("Expected atom")
        return self.raw[start:self.pos]

    def parse_dot_atom_text(self) -> str:
        start = self.pos
        if not self.is_atext(self.peek_char()):
            raise ValueError("Expected dot-atom-text starting with atext")
        while self.is_atext(self.peek_char()):
            self.consume_char()
        while self.peek_char() == '.':
            if self.pos + 1 < self.length and self.is_atext(self.raw[self.pos + 1]):
                self.consume_char()
                while self.is_atext(self.peek_char()):
                    self.consume_char()
            else:
                break
        return self.raw[start:self.pos]

    def parse_domain_literal_core(self) -> str:
        if not self.match_char('['):
            raise ValueError("Expected '['")
        
        content_parts = ['[']
        while True:
            fws = self.parse_fws()
            if fws:
                content_parts.append(fws.replace('\r\n', ''))
            
            c = self.peek_char()
            if c == ']':
                self.consume_char()
                content_parts.append(']')
                break
            elif c == '\\':
                if self.strict:
                    raise ValueError("Quoted-pair not allowed in strict domain-literal")
                qp = self.parse_quoted_pair()
                content_parts.append(qp[1:])
            elif c == '':
                raise ValueError("Unterminated domain-literal")
            else:
                if self.is_dtext(c):
                    content_parts.append(c)
                    self.consume_char()
                else:
                    raise ValueError(f"Invalid character in domain-literal: {c!r}")
                    
        return "".join(content_parts)

    def parse_word(self, comments: list[str]) -> str:
        self.parse_cfws_into(comments)
        if self.peek_char() == '"':
            val = self.parse_quoted_string_core()
            self.parse_cfws_into(comments)
            return val
        else:
            val = self.parse_atom_core()
            self.parse_cfws_into(comments)
            return val

    def clean_phrase(self, start_pos: int, end_pos: int) -> str:
        raw = self.raw[start_pos:end_pos].strip()
        if raw.startswith('"') and raw.endswith('"'):
            temp_state = ParserState(raw, self.strict)
            try:
                return temp_state.parse_quoted_string_core()
            except Exception:
                pass
        
        result = []
        paren_depth = 0
        i = 0
        while i < len(raw):
            c = raw[i]
            if c == '(':
                paren_depth += 1
            elif c == ')':
                if paren_depth > 0:
                    paren_depth -= 1
            elif paren_depth == 0:
                result.append(c)
            i += 1
            
        clean_str = "".join(result)
        clean_str = re.sub(r'\s+', ' ', clean_str).strip()
        return clean_str

    def parse_phrase(self, comments: list[str]) -> str:
        start_pos = self.pos
        words = []
        
        self.parse_cfws_into(comments)
        c = self.peek_char()
        if c == '"':
            w = self.parse_quoted_string_core()
        else:
            w = self.parse_atom_core()
        self.parse_cfws_into(comments)
        words.append((w, False))
        
        while True:
            pos_before_cfws = self.pos
            comments_before = list(comments)
            try:
                temp_comments = []
                self.parse_cfws_into(temp_comments)
                pos_after_cfws = self.pos
                
                has_space = False
                if pos_after_cfws > pos_before_cfws:
                    consumed = self.raw[pos_before_cfws:pos_after_cfws]
                    if any(ch.isspace() for ch in consumed):
                        has_space = True
                
                c = self.peek_char()
                if not self.strict and c == '.':
                    self.consume_char()
                    words.append(('.', has_space))
                    continue
                elif c == '"' or self.is_atext(c):
                    comments.extend(temp_comments)
                    if c == '"':
                        w = self.parse_quoted_string_core()
                    else:
                        w = self.parse_atom_core()
                    words.append((w, has_space))
                else:
                    self.pos = pos_before_cfws
                    break
            except ValueError:
                self.pos = pos_before_cfws
                comments.clear()
                comments.extend(comments_before)
                break
                
        result = ""
        for w, has_space in words:
            if has_space:
                result += " "
            elif result and w != '.' and not result.endswith('.'):
                result += " "
            result += w
        return result

    def parse_local_part(self, comments: list[str]) -> str:
        self.parse_cfws_into(comments)
        
        if self.strict:
            if self.peek_char() == '"':
                val = self.parse_quoted_string_core()
                self.parse_cfws_into(comments)
                return val
            else:
                val = self.parse_dot_atom_text()
                self.parse_cfws_into(comments)
                return val
        else:
            parts = []
            if self.peek_char() == '"':
                parts.append(self.parse_quoted_string_core())
            else:
                parts.append(self.parse_atom_core())
            self.parse_cfws_into(comments)
            
            while self.peek_char() == '.':
                self.consume_char()
                self.parse_cfws_into(comments)
                
                if self.peek_char() == '"':
                    parts.append(self.parse_quoted_string_core())
                else:
                    parts.append(self.parse_atom_core())
                self.parse_cfws_into(comments)
                
            return '.'.join(parts)

    def parse_domain(self, comments: list[str]) -> str:
        self.parse_cfws_into(comments)
        
        if self.peek_char() == '[':
            val = self.parse_domain_literal_core()
            self.parse_cfws_into(comments)
            return val
            
        if self.strict:
            val = self.parse_dot_atom_text()
            self.parse_cfws_into(comments)
            return val
        else:
            parts = []
            while True:
                self.parse_cfws_into(comments)
                c = self.peek_char()
                if c == '.':
                    self.consume_char()
                    parts.append('.')
                elif self.is_atext(c):
                    atom = self.parse_atom_core()
                    parts.append(atom)
                else:
                    break
            
            if not parts:
                raise ValueError("Expected domain in permissive mode")
            
            val = "".join(parts)
            self.parse_cfws_into(comments)
            return val

    def parse_addr_spec(self, comments: list[str]) -> tuple[str, str]:
        local_part = self.parse_local_part(comments)
        if not self.match_char('@'):
            raise ValueError("Expected '@'")
        domain = self.parse_domain(comments)
        return local_part, domain

    def parse_obs_route(self, comments: list[str]):
        while True:
            self.parse_cfws_into(comments)
            if self.match_char(','):
                continue
            break
            
        if not self.match_char('@'):
            raise ValueError("Expected '@' in obs-route")
            
        self.parse_domain(comments)
        
        while True:
            self.parse_cfws_into(comments)
            if self.match_char(','):
                self.parse_cfws_into(comments)
                if self.match_char('@'):
                    self.parse_domain(comments)
                continue
            break
            
        if not self.match_char(':'):
            raise ValueError("Expected ':' after route")

    def parse_angle_addr(self, comments: list[str]) -> tuple[str, str]:
        self.parse_cfws_into(comments)
        if not self.match_char('<'):
            raise ValueError("Expected '<'")
        self.parse_cfws_into(comments)
        
        if not self.strict:
            pos_before = self.pos
            comments_before = list(comments)
            try:
                while True:
                    self.parse_cfws_into(comments)
                    if self.match_char(','):
                        continue
                    break
                if self.peek_char() == '@':
                    self.pos = pos_before
                    comments.clear()
                    comments.extend(comments_before)
                    self.parse_obs_route(comments)
                else:
                    self.pos = pos_before
                    comments.clear()
                    comments.extend(comments_before)
            except ValueError:
                self.pos = pos_before
                comments.clear()
                comments.extend(comments_before)
                
        local_part, domain = self.parse_addr_spec(comments)
        
        self.parse_cfws_into(comments)
        if not self.match_char('>'):
            raise ValueError("Expected '>'")
        self.parse_cfws_into(comments)
        
        return local_part, domain

    def parse_mailbox(self) -> RFC5322Address:
        start_pos = self.pos
        comments = []
        
        pos_before = self.pos
        try:
            temp_comments = []
            self.parse_cfws_into(temp_comments)
            if self.peek_char() == '<':
                comments.extend(temp_comments)
                local_part, domain = self.parse_angle_addr(comments)
                source = self.raw[start_pos:self.pos]
                return RFC5322Address(
                    display_name=None,
                    local_part=local_part,
                    domain=domain,
                    is_group=False,
                    group_members=[],
                    comments=comments,
                    source=source
                )
                
            self.pos = pos_before
            display_name = self.parse_phrase(comments)
            local_part, domain = self.parse_angle_addr(comments)
            source = self.raw[start_pos:self.pos]
            return RFC5322Address(
                display_name=display_name,
                local_part=local_part,
                domain=domain,
                is_group=False,
                group_members=[],
                comments=comments,
                source=source
            )
        except ValueError:
            self.pos = pos_before
            
        comments = []
        local_part, domain = self.parse_addr_spec(comments)
        source = self.raw[start_pos:self.pos]
        return RFC5322Address(
            display_name=None,
            local_part=local_part,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=comments,
            source=source
        )

    def parse_group(self) -> RFC5322Address:
        start_pos = self.pos
        comments = []
        
        display_name = self.parse_phrase(comments)
        if not self.match_char(':'):
            raise ValueError("Expected ':'")
            
        self.parse_cfws_into(comments)
        members = []
        
        while True:
            self.parse_cfws_into(comments)
            c = self.peek_char()
            if c == ';':
                break
            elif c == '':
                raise ValueError("Expected ';' at end of group")
            elif c == ',':
                if self.strict:
                    if not members:
                        raise ValueError("Leading comma in group-list not allowed in strict mode")
                    self.consume_char()
                    self.parse_cfws_into(comments)
                    members.append(self.parse_mailbox())
                else:
                    self.consume_char()
                    continue
            else:
                if self.strict and members:
                    raise ValueError("Expected ',' between mailboxes in strict mode")
                members.append(self.parse_mailbox())
                
        if not self.match_char(';'):
            raise ValueError("Expected ';'")
        self.parse_cfws_into(comments)
        
        source = self.raw[start_pos:self.pos]
        return RFC5322Address(
            display_name=display_name,
            local_part="",
            domain="",
            is_group=True,
            group_members=members,
            comments=comments,
            source=source
        )

    def parse_address(self) -> RFC5322Address:
        pos_before = self.pos
        try:
            return self.parse_group()
        except ValueError:
            self.pos = pos_before
            
        return self.parse_mailbox()


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
        self.strict = strict
    
    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        if self.strict and len(raw.rstrip('\r\n')) > 998:
            raise ValueError("Line length exceeds 998 characters limit")
            
        state = ParserState(raw, self.strict)
        comments = []
        state.parse_cfws_into(comments)
        
        addr = state.parse_address()
        addr.comments = comments + addr.comments
        
        state.parse_cfws_into(addr.comments)
        
        if state.peek_char() != '':
            raise ValueError("Extra characters at end of address")
            
        addr.source = raw
        return addr
    
    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        if self.strict and len(raw.rstrip('\r\n')) > 998:
            raise ValueError("Line length exceeds 998 characters limit")
            
        state = ParserState(raw, self.strict)
        addresses = []
        comments = []
        
        state.parse_cfws_into(comments)
        while True:
            state.parse_cfws_into(comments)
            if state.peek_char() == '':
                break
                
            if state.match_char(','):
                if state.strict:
                    raise ValueError("Leading or consecutive commas in address-list not allowed in strict mode")
                continue
                
            addr = state.parse_address()
            addr.comments = comments + addr.comments
            comments = []
            addresses.append(addr)
            
            state.parse_cfws_into(comments)
            if state.peek_char() == '':
                break
            elif state.match_char(','):
                state.parse_cfws_into(comments)
                if state.peek_char() == '' and state.strict:
                    raise ValueError("Trailing comma in address-list not allowed in strict mode")
                continue
            else:
                raise ValueError("Expected ',' or EOF in address-list")
                
        state.parse_cfws_into(comments)
        if state.peek_char() != '':
            raise ValueError("Extra characters at end of address-list")
            
        if addresses and comments:
            addresses[-1].comments.extend(comments)
            
        return addresses
    
    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        if self.strict and len(raw.rstrip('\r\n')) > 998:
            raise ValueError("Line length exceeds 998 characters limit")
            
        state = ParserState(raw, self.strict)
        mailboxes = []
        comments = []
        
        state.parse_cfws_into(comments)
        while True:
            state.parse_cfws_into(comments)
            if state.peek_char() == '':
                break
                
            if state.match_char(','):
                if state.strict:
                    raise ValueError("Leading or consecutive commas in mailbox-list not allowed in strict mode")
                continue
                
            addr = state.parse_mailbox()
            addr.comments = comments + addr.comments
            comments = []
            mailboxes.append(addr)
            
            state.parse_cfws_into(comments)
            if state.peek_char() == '':
                break
            elif state.match_char(','):
                state.parse_cfws_into(comments)
                if state.peek_char() == '' and state.strict:
                    raise ValueError("Trailing comma in mailbox-list not allowed in strict mode")
                continue
            else:
                raise ValueError("Expected ',' or EOF in mailbox-list")
                
        state.parse_cfws_into(comments)
        if state.peek_char() != '':
            raise ValueError("Extra characters at end of mailbox-list")
            
        if mailboxes and comments:
            mailboxes[-1].comments.extend(comments)
            
        return mailboxes
