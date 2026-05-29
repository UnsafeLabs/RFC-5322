from typing import List, Optional, Tuple

class RFC5322Address:
    """Parsed RFC 5322 email address."""
    def __init__(self) -> None:
        self.display_name: Optional[str] = None
        self.local_part: str = ""
        self.domain: str = ""
        self.is_group: bool = False
        self.group_members: List['RFC5322Address'] = []
        self.comments: List[str] = []
        self.source: str = ""

    def __repr__(self) -> str:
        if self.is_group:
            members_str = ", ".join(repr(m) for m in self.group_members)
            return f"Group(name={repr(self.display_name)}, members=[{members_str}], comments={self.comments})"
        else:
            return f"Mailbox(name={repr(self.display_name)}, local_part={repr(self.local_part)}, domain={repr(self.domain)}, comments={self.comments})"

def is_atext(c: str) -> bool:
    if not c:
        return False
    if c.isalnum():
        return True
    return c in "!#$%&'*+-/=?^_`{|}~"

def is_qtext(c: str, strict: bool) -> bool:
    if not c:
        return False
    o = ord(c)
    if o == 33 or (35 <= o <= 91) or (93 <= o <= 126):
        return True
    if not strict:
        if (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
            return True
    return False

def is_ctext(c: str, strict: bool) -> bool:
    if not c:
        return False
    o = ord(c)
    if (33 <= o <= 39) or (42 <= o <= 91) or (93 <= o <= 126):
        return True
    if not strict:
        if (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
            return True
    return False

def is_dtext(c: str, strict: bool) -> bool:
    if not c:
        return False
    o = ord(c)
    if (33 <= o <= 90) or (94 <= o <= 126):
        return True
    if not strict:
        if (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
            return True
    return False

def unquote_string(s: str) -> str:
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        content = s[1:-1]
        res = []
        i = 0
        while i < len(content):
            if content[i] == '\\' and i + 1 < len(content):
                res.append(content[i+1])
                i += 2
            else:
                res.append(content[i])
                i += 1
        return "".join(res)
    return s

class ParserState:
    def __init__(self, s: str, strict: bool) -> None:
        self.s = s
        self.strict = strict
        self.pos = 0
        self.comments: List[str] = []

    def parse_fws(self) -> str:
        start = self.pos
        wsp1 = 0
        while self.pos < len(self.s) and self.s[self.pos] in " \t":
            self.pos += 1
            wsp1 += 1
        
        has_crlf = False
        if self.pos + 1 < len(self.s) and self.s[self.pos:self.pos+2] == "\r\n":
            self.pos += 2
            has_crlf = True
        elif not self.strict and self.pos < len(self.s) and self.s[self.pos] in "\r\n":
            self.pos += 1
            has_crlf = True
                
        if has_crlf:
            wsp2 = 0
            while self.pos < len(self.s) and self.s[self.pos] in " \t":
                self.pos += 1
                wsp2 += 1
            if wsp2 == 0:
                self.pos = start + wsp1
                return self.s[start:start+wsp1]
            return self.s[start:self.pos]
        return self.s[start:self.pos]

    def parse_comment(self) -> str:
        if self.pos >= len(self.s) or self.s[self.pos] != '(':
            raise ValueError("Expected '(' at start of comment")
        self.pos += 1
        
        comment_content = []
        
        while self.pos < len(self.s):
            fws_str = self.parse_fws()
            if fws_str:
                comment_content.append(fws_str)
                
            if self.pos >= len(self.s):
                raise ValueError("Unclosed comment")
            
            c = self.s[self.pos]
            if c == ')':
                self.pos += 1
                return "".join(comment_content)
            elif c == '(':
                nested = self.parse_comment()
                comment_content.append("(" + nested + ")")
            elif c == '\\':
                qp = self.parse_quoted_pair()
                comment_content.append(qp)
            elif is_ctext(c, self.strict):
                comment_content.append(c)
                self.pos += 1
            elif not self.strict and ord(c) in [10, 13]:
                comment_content.append(c)
                self.pos += 1
            else:
                raise ValueError(f"Invalid character in comment: {repr(c)}")
                
        raise ValueError("Unclosed comment")

    def parse_cfws(self) -> None:
        while True:
            self.parse_fws()
            if self.pos < len(self.s) and self.s[self.pos] == '(':
                comment_text = self.parse_comment()
                self.comments.append(comment_text)
            else:
                break
        self.parse_fws()

    def parse_quoted_pair(self) -> str:
        if self.pos >= len(self.s) or self.s[self.pos] != '\\':
            raise ValueError("Expected '\\' at start of quoted-pair")
        if self.pos + 1 >= len(self.s):
            raise ValueError("Trailing '\\' at end of input")
        val = self.s[self.pos + 1]
        o = ord(val)
        if self.strict:
            if not (33 <= o <= 126 or o == 32 or o == 9):
                raise ValueError(f"Invalid character in quoted-pair in strict mode: {repr(val)}")
        self.pos += 2
        return val

    def parse_quoted_string(self) -> str:
        if self.pos >= len(self.s) or self.s[self.pos] != '"':
            raise ValueError("Expected '\"' at start of quoted-string")
        
        start_pos = self.pos
        self.pos += 1
        
        while self.pos < len(self.s):
            self.parse_fws()
            if self.pos >= len(self.s):
                raise ValueError("Unclosed quoted-string")
            
            c = self.s[self.pos]
            if c == '"':
                self.pos += 1
                return self.s[start_pos:self.pos]
            elif c == '\\':
                self.parse_quoted_pair()
            elif is_qtext(c, self.strict):
                self.pos += 1
            elif not self.strict and ord(c) in [10, 13]:
                self.pos += 1
            else:
                raise ValueError(f"Invalid character in quoted-string: {repr(c)}")
                
        raise ValueError("Unclosed quoted-string")

    def parse_domain_literal(self) -> str:
        if self.pos >= len(self.s) or self.s[self.pos] != '[':
            raise ValueError("Expected '[' at start of domain-literal")
            
        start_pos = self.pos
        self.pos += 1
        
        while self.pos < len(self.s):
            self.parse_fws()
            if self.pos >= len(self.s):
                raise ValueError("Unclosed domain-literal")
                
            c = self.s[self.pos]
            if c == ']':
                self.pos += 1
                return self.s[start_pos:self.pos]
            elif c == '\\':
                if self.strict:
                    raise ValueError("Quoted-pair not allowed in domain-literal in strict mode")
                else:
                    self.parse_quoted_pair()
            elif is_dtext(c, self.strict):
                self.pos += 1
            else:
                raise ValueError(f"Invalid character in domain-literal: {repr(c)}")
                
        raise ValueError("Unclosed domain-literal")

    def parse_dot_atom_text(self) -> str:
        start_pos = self.pos
        if self.pos >= len(self.s) or not is_atext(self.s[self.pos]):
            raise ValueError("Expected atext at start of dot-atom-text")
        self.pos += 1
        
        while self.pos < len(self.s) and is_atext(self.s[self.pos]):
            self.pos += 1
            
        while self.pos < len(self.s) and self.s[self.pos] == '.':
            if self.pos + 1 >= len(self.s) or not is_atext(self.s[self.pos + 1]):
                break
            self.pos += 2
            while self.pos < len(self.s) and is_atext(self.s[self.pos]):
                self.pos += 1
                
        return self.s[start_pos:self.pos]

    def parse_word(self) -> str:
        self.parse_cfws()
        if self.pos >= len(self.s):
            raise ValueError("Expected word")
            
        if self.s[self.pos] == '"':
            val = self.parse_quoted_string()
            self.parse_cfws()
            return val
        else:
            start_pos = self.pos
            if not is_atext(self.s[self.pos]):
                raise ValueError("Expected atext inside atom")
            while self.pos < len(self.s) and is_atext(self.s[self.pos]):
                self.pos += 1
            val = self.s[start_pos:self.pos]
            self.parse_cfws()
            return val

    def parse_local_part(self) -> str:
        self.parse_cfws()
        
        if self.pos >= len(self.s):
            raise ValueError("Empty local-part")
            
        if self.strict:
            if self.s[self.pos] == '"':
                lp_val = self.parse_quoted_string()
                self.parse_cfws()
                return lp_val
            else:
                lp_val = self.parse_dot_atom_text()
                self.parse_cfws()
                return lp_val
        else:
            words = []
            words.append(self.parse_word())
            
            while self.pos < len(self.s) and self.s[self.pos] == '.':
                self.pos += 1
                words.append(self.parse_word())
                
            return ".".join(words)

    def parse_atom_value(self) -> str:
        self.parse_cfws()
        if self.pos >= len(self.s) or not is_atext(self.s[self.pos]):
            raise ValueError("Expected atext inside atom")
        start = self.pos
        while self.pos < len(self.s) and is_atext(self.s[self.pos]):
            self.pos += 1
        val = self.s[start:self.pos]
        self.parse_cfws()
        return val

    def parse_domain(self) -> str:
        self.parse_cfws()
        if self.pos >= len(self.s):
            raise ValueError("Empty domain")
            
        if self.s[self.pos] == '[':
            val = self.parse_domain_literal()
            self.parse_cfws()
            return val
            
        if self.strict:
            val = self.parse_dot_atom_text()
            self.parse_cfws()
            return val
        else:
            atoms = []
            atoms.append(self.parse_atom_value())
            while self.pos < len(self.s) and self.s[self.pos] == '.':
                self.pos += 1
                atoms.append(self.parse_atom_value())
            return ".".join(atoms)

    def parse_addr_spec(self) -> Tuple[str, str]:
        lp = self.parse_local_part()
        
        if self.pos >= len(self.s) or self.s[self.pos] != '@':
            raise ValueError("Expected '@' after local-part")
        self.pos += 1
        
        dom = self.parse_domain()
        return lp, dom

    def parse_angle_addr(self) -> Tuple[str, str]:
        self.parse_cfws()
        if self.pos >= len(self.s) or self.s[self.pos] != '<':
            raise ValueError("Expected '<' at start of angle-addr")
        self.pos += 1
        
        self.parse_cfws()
        
        if not self.strict:
            colon_pos = -1
            depth = 0
            for i in range(self.pos, len(self.s)):
                if self.s[i] == '(':
                    depth += 1
                elif self.s[i] == ')':
                    depth -= 1
                elif self.s[i] == '>' and depth == 0:
                    break
                elif self.s[i] == ':' and depth == 0:
                    colon_pos = i
                    break
            if colon_pos != -1:
                self.pos = colon_pos + 1
                self.parse_cfws()
                
        lp, dom = self.parse_addr_spec()
        
        self.parse_cfws()
        if self.pos >= len(self.s) or self.s[self.pos] != '>':
            raise ValueError("Expected '>' at end of angle-addr")
        self.pos += 1
        
        self.parse_cfws()
        return lp, dom

    def parse_phrase(self) -> str:
        words = []
        self.parse_cfws()
        
        while self.pos < len(self.s):
            temp_pos = self.pos
            self.parse_cfws()
            if self.pos >= len(self.s) or self.s[self.pos] in "<:":
                self.pos = temp_pos
                break
                
            if not self.strict and self.s[self.pos] == '.':
                words.append(".")
                self.pos += 1
                self.parse_cfws()
                continue
                
            if self.s[self.pos] == '"':
                qs = self.parse_quoted_string()
                words.append(unquote_string(qs))
            else:
                start_atom = self.pos
                if not is_atext(self.s[self.pos]):
                    self.pos = temp_pos
                    break
                while self.pos < len(self.s) and is_atext(self.s[self.pos]):
                    self.pos += 1
                words.append(self.s[start_atom:self.pos])
                
            self.parse_cfws()
            
        if not words:
            raise ValueError("Expected phrase")
            
        return " ".join(words)

    def parse_mailbox(self) -> RFC5322Address:
        start_pos = self.pos
        comments_before = len(self.comments)
        
        try:
            disp_name = None
            temp_pos = self.pos
            self.parse_cfws()
            has_angle = (self.pos < len(self.s) and self.s[self.pos] == '<')
            self.pos = temp_pos
            
            if not has_angle:
                disp_name = self.parse_phrase()
                
            lp, dom = self.parse_angle_addr()
            
            addr = RFC5322Address()
            addr.display_name = disp_name
            addr.local_part = lp
            addr.domain = dom
            addr.is_group = False
            addr.group_members = []
            addr.comments = self.comments[comments_before:]
            addr.source = self.s[start_pos:self.pos]
            return addr
            
        except ValueError:
            self.pos = start_pos
            self.comments = self.comments[:comments_before]
            
            lp, dom = self.parse_addr_spec()
            
            addr = RFC5322Address()
            addr.display_name = None
            addr.local_part = lp
            addr.domain = dom
            addr.is_group = False
            addr.group_members = []
            addr.comments = self.comments[comments_before:]
            addr.source = self.s[start_pos:self.pos]
            return addr

    def parse_group(self) -> RFC5322Address:
        start_pos = self.pos
        comments_before = len(self.comments)
        
        disp_name = self.parse_phrase()
        
        if self.pos >= len(self.s) or self.s[self.pos] != ':':
            raise ValueError("Expected ':' after display-name in group")
        self.pos += 1
        
        self.parse_cfws()
        
        members = []
        if self.pos < len(self.s) and self.s[self.pos] == ';':
            pass
        else:
            while self.pos < len(self.s):
                self.parse_cfws()
                if self.pos < len(self.s) and self.s[self.pos] == ';':
                    break
                    
                if not self.strict and self.s[self.pos] == ',':
                    self.pos += 1
                    continue
                    
                members.append(self.parse_mailbox())
                
                self.parse_cfws()
                if self.pos < len(self.s) and self.s[self.pos] == ',':
                    self.pos += 1
                elif self.pos < len(self.s) and self.s[self.pos] == ';':
                    break
                else:
                    raise ValueError("Expected ',' or ';' in group-list")
                    
        if self.pos >= len(self.s) or self.s[self.pos] != ';':
            raise ValueError("Expected ';' at end of group")
        self.pos += 1
        
        self.parse_cfws()
        
        addr = RFC5322Address()
        addr.display_name = disp_name
        addr.local_part = ""
        addr.domain = ""
        addr.is_group = True
        addr.group_members = members
        addr.comments = self.comments[comments_before:]
        addr.source = self.s[start_pos:self.pos]
        return addr

    def parse_address(self) -> RFC5322Address:
        start_pos = self.pos
        comments_before = len(self.comments)
        try:
            return self.parse_group()
        except ValueError:
            self.pos = start_pos
            self.comments = self.comments[:comments_before]
            return self.parse_mailbox()

class AddressParser:
    """
    RFC 5322 compliant email address parser.
    
    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    """
    def __init__(self, strict: bool = True) -> None:
        self.strict = strict

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        if len(raw) > 998:
            raise ValueError("Input exceeds maximum line length limit of 998 characters")
        state = ParserState(raw, self.strict)
        state.parse_cfws()
        addr = state.parse_address()
        state.parse_cfws()
        if state.pos < len(state.s):
            raise ValueError(f"Trailing garbage after address: {repr(state.s[state.pos:])}")
        addr.comments = state.comments
        return addr

    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        if len(raw) > 998:
            raise ValueError("Input exceeds maximum line length limit of 998 characters")
        state = ParserState(raw, self.strict)
        addresses = []
        
        while state.pos < len(state.s):
            if not self.strict and state.s[state.pos] == ',':
                state.pos += 1
                continue
                
            state.comments = []
            state.parse_cfws()
            addr = state.parse_address()
            state.parse_cfws()
            addr.comments = state.comments
            addresses.append(addr)
            
            if state.pos < len(state.s) and state.s[state.pos] == ',':
                state.pos += 1
            elif state.pos < len(state.s):
                raise ValueError("Expected ',' between addresses in list")
                
        return addresses

    def parse_mailbox_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        if len(raw) > 998:
            raise ValueError("Input exceeds maximum line length limit of 998 characters")
        state = ParserState(raw, self.strict)
        mailboxes = []
        
        while state.pos < len(state.s):
            if not self.strict and state.s[state.pos] == ',':
                state.pos += 1
                continue
                
            state.comments = []
            state.parse_cfws()
            addr = state.parse_mailbox()
            state.parse_cfws()
            addr.comments = state.comments
            mailboxes.append(addr)
            
            if state.pos < len(state.s) and state.s[state.pos] == ',':
                state.pos += 1
            elif state.pos < len(state.s):
                raise ValueError("Expected ',' between mailboxes in list")
                
        return mailboxes
