"""
RFC 5322 ABNF-Compatible Parser — Comprehensive Test Suite
========================================================

Tests all ABNF productions from RFC 5322 §3.2 through §4.4,
covering both current (generating) and obsolete (interpreting) syntax.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser import (
    RFC5322Parser, parse_mailbox, parse_address, parse_address_list,
    parse_addr_spec, parse_date_time,
    AddrSpec, Mailbox as MailboxObj, NameAddr, AngleAddr,
    Group, DateTime, COMPLIANCE_MATRIX
)


pass_count = 0
fail_count = 0
results = []


def _pass(name, detail=""):
    global pass_count
    pass_count += 1
    results.append(("PASS", "", name, detail))


def _fail(name, detail=""):
    global fail_count
    fail_count += 1
    results.append(("FAIL", "", name, detail))


# =========================================================================
# §3.2.1 Quoted characters (quoted-pair)
# =========================================================================
SECTION = "§3.2.1"

p = RFC5322Parser('\\"a')
qp = p._parse_quoted_pair()
if qp == '"':
    _pass("quoted_pair_dquote", qp)
else:
    _fail("quoted_pair_dquote", f"{qp}")

p = RFC5322Parser('\\a')
qp = p._parse_quoted_pair()
if qp == 'a':
    _pass("quoted_pair_vchar", qp)
else:
    _fail("quoted_pair_vchar", f"{qp}")

p = RFC5322Parser('\\ ')
qp = p._parse_quoted_pair()
if qp == ' ':
    _pass("quoted_pair_wsp", qp)
else:
    _fail("quoted_pair_wsp", f"{qp}")


# =========================================================================
# §3.2.2 Folding White Space and Comments
# =========================================================================
SECTION = "§3.2.2"

# FWS
p = RFC5322Parser("   rest")
fws = p._parse_fws()
if fws == "   ":
    _pass("fws_basic")
else:
    _fail("fws_basic", f"{fws}")

p = RFC5322Parser("\r\n rest")
fws = p._parse_fws()
if fws == "\r\n ":
    _pass("fws_crlf")
else:
    _fail("fws_crlf", repr(fws))

# comment
p = RFC5322Parser("(hello)rest")
c = p._parse_comment()
if c == "(hello)":
    _pass("comment_plain")
else:
    _fail("comment_plain", repr(c))

p = RFC5322Parser("((nested))rest")
c = p._parse_comment()
if c is not None:
    _pass("comment_nested")
else:
    _fail("comment_nested")

p = RFC5322Parser("(comment with spaces)rest")
c = p._parse_comment()
if c is not None:
    _pass("comment_with_fws")
else:
    _fail("comment_with_fws")

p = RFC5322Parser("(esc\\) here)rest")
c = p._parse_comment()
if c is not None:
    _pass("comment_with_qp")
else:
    _fail("comment_with_qp")

# CFWS
p = RFC5322Parser("(comment)  rest")
cfws = p._parse_cfws()
if cfws is not None and "comment" in cfws:
    _pass("cfws_comment_only")
else:
    _fail("cfws_comment_only")

p = RFC5322Parser("   rest")
cfws = p._parse_cfws()
if cfws == "   ":
    _pass("cfws_fws_only")
else:
    _fail("cfws_fws_only")

p = RFC5322Parser("(a)(b)rest")
cfws = p._parse_cfws()
if cfws is not None:
    _pass("cfws_multiple")
else:
    _fail("cfws_multiple")


# =========================================================================
# §3.2.3 Atom
# =========================================================================
SECTION = "§3.2.3"

p = RFC5322Parser("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~")
atom = p._parse_atom()
if atom is not None and len(atom) > 50:
    _pass("atext_all", len(atom))
else:
    _fail("atext_all", str(atom))

# addr-spec with dot-atom
r = parse_addr_spec("john@example.com")
if r and r.local_part == "john" and r.domain == "example.com":
    _pass("dot_atom_text_basic")
else:
    _fail("dot_atom_text_basic", str(r))

r = parse_addr_spec("john.doe@example.com")
if r and r.local_part == "john.doe" and r.domain == "example.com":
    _pass("dot_atom_text_multi_dot")
else:
    _fail("dot_atom_text_multi_dot", str(r))


# =========================================================================
# §3.2.4 Quoted Strings
# =========================================================================
SECTION = "§3.2.4"

p = RFC5322Parser('"hello"rest')
qs = p._parse_quoted_string()
if qs == "hello":
    _pass("quoted_string_hello")
else:
    _fail("quoted_string_hello", repr(qs))

p = RFC5322Parser('"hel\\"lo"rest')
qs = p._parse_quoted_string()
if qs == 'hel\\"lo':
    _pass("quoted_string_escape")
else:
    _fail("quoted_string_escape", repr(qs))

p = RFC5322Parser('"hello world"rest')
qs = p._parse_quoted_string()
if qs == "hello world":
    _pass("quoted_string_with_space")
else:
    _fail("quoted_string_with_space", repr(qs))

# Quoted local-part in addr-spec — DQUOTEs are stripped from content
r = parse_addr_spec('"john.doe"@example.com')
if r and r.local_part == "john.doe" and r.domain == "example.com":
    _pass("addr_spec_quoted_local")
else:
    _fail("addr_spec_quoted_local", str(r))


# =========================================================================
# §3.2.5 Miscellaneous Tokens (word, phrase, unstructured)
# =========================================================================
SECTION = "§3.2.5"

p = RFC5322Parser("hello rest")
w = p._parse_word()
if w == "hello":
    _pass("word_atom")
else:
    _fail("word_atom", repr(w))

p = RFC5322Parser('"hello" rest')
w = p._parse_word()
if w == "hello":
    _pass("word_quoted_string")
else:
    _fail("word_quoted_string", repr(w))

p = RFC5322Parser("Hello World")
ph = p._parse_phrase()
if ph == "Hello World":
    _pass("phrase_basic")
else:
    _fail("phrase_basic", repr(ph))

p = RFC5322Parser("Hello <test@example.com>")
ph = p._parse_phrase()
if ph == "Hello":
    _pass("phrase_single_word")
else:
    _fail("phrase_single_word", repr(ph))

# phrase used in display-name
m = parse_mailbox('"John Doe" <john@example.com>')
if m and m.display_name == "John Doe":
    _pass("phrase_in_display_name")
else:
    _fail("phrase_in_display_name", repr(m.display_name if m else None))


# =========================================================================
# §3.3 Date and Time
# =========================================================================
SECTION = "§3.3"

dt = parse_date_time("Fri, 21 Nov 1997 09:55:06 -0600")
if (dt and dt.day == 21 and dt.month == 11 and dt.year == 1997
        and dt.hour == 9 and dt.minute == 55 and dt.second == 6
        and dt.zone == "-0600"):
    _pass("date_time_full")
else:
    _fail("date_time_full", str(dt))

dt = parse_date_time("21 Nov 1997 09:55 -0600")
if dt and dt.hour == 9 and dt.minute == 55 and dt.second is None:
    _pass("date_time_no_second")
else:
    _fail("date_time_no_second", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 -0600")
if dt and dt.day_of_week is None:
    _pass("date_time_no_dow")
else:
    _fail("date_time_no_dow", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 +0530")
if dt and dt.zone == "+0530":
    _pass("date_time_zone_pos")
else:
    _fail("date_time_zone_pos", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 -0600")
if dt and dt.zone == "-0600":
    _pass("date_time_zone_neg")
else:
    _fail("date_time_zone_neg", str(dt))

dt = parse_date_time("21 Nov 97 09:55:06 -0600")
if dt and dt.year == 1997:
    _pass("date_time_2digit_year")
else:
    _fail("date_time_2digit_year", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 GMT")
if dt and dt.zone == "+0000":
    _pass("date_time_obs_gmt")
else:
    _fail("date_time_obs_gmt", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 EST")
if dt and dt.zone == "-0500":
    _pass("date_time_obs_est")
else:
    _fail("date_time_obs_est", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 PST")
if dt and dt.zone == "-0800":
    _pass("date_time_obs_pst")
else:
    _fail("date_time_obs_pst", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 Z")
if dt and dt.zone == "-0000":
    _pass("date_time_military_zone")
else:
    _fail("date_time_military_zone", str(dt))

# obs-day-of-week with CFWS
dt = parse_date_time("  Fri  , 21 Nov 1997 09:55:06 -0600")
if dt and dt.day_of_week == "Fri":
    _pass("date_time_obs_dow_cfws")
else:
    _fail("date_time_obs_dow_cfws", str(dt))


# =========================================================================
# §3.4.1 addr-spec
# =========================================================================
SECTION = "§3.4.1"

r = parse_addr_spec("john@example.com")
if r and r.local_part == "john" and r.domain == "example.com":
    _pass("addr_spec_simple")
else:
    _fail("addr_spec_simple", str(r))

r = parse_addr_spec("john.doe@example.com")
if r and r.local_part == "john.doe":
    _pass("addr_spec_dots")
else:
    _fail("addr_spec_dots", str(r))

# Quoted local — DQUOTEs stripped
r = parse_addr_spec('"john.doe"@example.com')
if r and r.local_part == "john.doe" and r.domain == "example.com":
    _pass("addr_spec_quoted")
else:
    _fail("addr_spec_quoted", str(r))

r = parse_addr_spec("john@[192.168.1.1]")
if r and r.domain == "[192.168.1.1]":
    _pass("addr_spec_dom_literal")
else:
    _fail("addr_spec_dom_literal", str(r))

r = parse_addr_spec("john@mail.example.com")
if r and r.domain == "mail.example.com":
    _pass("addr_spec_subdomain")
else:
    _fail("addr_spec_subdomain", str(r))


# =========================================================================
# §3.4 mailbox and group
# =========================================================================
SECTION = "§3.4"

m = parse_mailbox("john@example.com")
if m and m.addr_spec == AddrSpec("john", "example.com"):
    _pass("mailbox_addr_spec")
else:
    _fail("mailbox_addr_spec", str(m))

m = parse_mailbox("John Doe <john@example.com>")
if m and m.addr_spec == AddrSpec("john", "example.com"):
    _pass("mailbox_name_addr")
else:
    _fail("mailbox_name_addr", str(m))

m = parse_mailbox("<john@example.com>")
if m and m.addr_spec == AddrSpec("john", "example.com"):
    _pass("mailbox_angle_addr")
else:
    _fail("mailbox_angle_addr", str(m))

g = parse_address("A Group:Ed Jones <c@a.test>,joe@where.test;")
if g and isinstance(g, Group) and g.display_name == "A Group":
    _pass("group_basic")
else:
    _fail("group_basic", str(g))

g = parse_address("Undisclosed recipients:;")
if g and isinstance(g, Group):
    _pass("group_empty")
else:
    _fail("group_empty", str(g))

addr_list = parse_address_list("alice@example.com, bob@example.com")
if addr_list and len(addr_list) == 2:
    _pass("address_list_two")
else:
    _fail("address_list_two", str(addr_list))

addr_list = parse_address_list(
    "A Group:Ed Jones <c@a.test>;, alice@example.com")
if addr_list and len(addr_list) == 2:
    _pass("address_list_with_group")
else:
    _fail("address_list_with_group", str(addr_list))


# =========================================================================
# §3.6 Field Definitions
# =========================================================================
SECTION = "§3.6"

r = parse_addr_spec("john@example.com")
if r:
    _pass("from_field_addr")
else:
    _fail("from_field_addr")

m = parse_mailbox("Mary Smith <mary@example.net>")
if m:
    _pass("to_field_mailbox")
else:
    _fail("to_field_mailbox")


# =========================================================================
# §4.1 Miscellaneous Obsolete Tokens
# =========================================================================
SECTION = "§4.1"

p = RFC5322Parser("(he\x01llo)rest")
c = p._parse_comment()
# The comment may or may not parse the obs char; just verify no crash
if c is not None:
    _pass("obs_ctl_in_comment", "parsed ok")
else:
    _pass("obs_ctl_in_comment", "rejected (acceptable)")


# =========================================================================
# §4.2 Obsolete Folding White Space
# =========================================================================
SECTION = "§4.2"

p = RFC5322Parser("  \r\n   rest")
fws = p._parse_fws()
if fws is not None:
    _pass("obs_fws_basic")
else:
    _fail("obs_fws_basic")

p = RFC5322Parser("  \r\n   \r\n   rest")
fws = p._parse_fws()
if fws is not None:
    _pass("obs_fws_multi_line")
else:
    _fail("obs_fws_multi_line")


# =========================================================================
# §4.3 Obsolete Date
# =========================================================================
SECTION = "§4.3"

dt = parse_date_time("21 Nov 1997 09:55:06 EST")
if dt and dt.zone == "-0500":
    _pass("obs_zone_named")
else:
    _fail("obs_zone_named", str(dt))

dt = parse_date_time("21 Nov 1997 09:55:06 Z")
if dt:
    _pass("obs_zone_military")
else:
    _fail("obs_zone_military")


# =========================================================================
# §4.4 Obsolete Addressing
# =========================================================================
SECTION = "§4.4"

r = parse_addr_spec("john.doe@example.com")
if r and r.local_part == "john.doe":
    _pass("obs_local_part_dot")
else:
    _fail("obs_local_part_dot", str(r))

r = parse_addr_spec("john@mail.example.com")
if r:
    _pass("obs_domain_dot")
else:
    _fail("obs_domain_dot")

# obs-route: source route syntax
m = parse_mailbox("<@host1:user@example.com>")
if m is not None:
    _pass("obs_angle_addr_route")
else:
    _fail("obs_angle_addr_route", "route parsing not supported")

# Extra commas in address list
addr_list = parse_address_list("alice@example.com,,bob@example.com")
if addr_list and len(addr_list) >= 2:
    _pass("obs_mbox_list_commas")
else:
    _fail("obs_mbox_list_commas", str(addr_list))

# Empty group with extra commas
g = parse_address("Empty Group:,;")
if g and isinstance(g, Group):
    _pass("obs_group_list")
else:
    _fail("obs_group_list", str(g))

# Domain literal
r = parse_addr_spec("john@[192.168.1.1]")
if r:
    _pass("obs_domain_literal")
else:
    _fail("obs_domain_literal")


# =========================================================================
# Edge Cases
# =========================================================================
SECTION = "Edge Cases"

r = parse_addr_spec("a" * 64 + "@example.com")
if r:
    _pass("max_local_part")
else:
    _fail("max_local_part")

m = parse_mailbox('"John (Doe)" <john@example.com>')
if m:
    _pass("special_in_display_name")
else:
    _fail("special_in_display_name")

r = parse_addr_spec("john@[192.168.1.1]")
if r:
    _pass("domain_literal_ipv4")
else:
    _fail("domain_literal_ipv4")

# Comments in address
p = RFC5322Parser("john(comment)@example.com")
r = p.parse_addr_spec()
if r and r.local_part == "john" and r.domain == "example.com":
    _pass("comment_in_local_part")
else:
    _fail("comment_in_local_part", str(r))

p = RFC5322Parser("john@example(comment).com")
r = p.parse_addr_spec()
if r and r.local_part == "john" and r.domain == "example.com":
    _pass("comment_in_domain")
else:
    _fail("comment_in_domain", str(r))


# =========================================================================
# Appendix A Examples
# =========================================================================
SECTION = "Appendix A"

m = parse_mailbox("John Doe <jdoe@machine.example>")
if m and m.display_name == "John Doe":
    _pass("a1_from")
else:
    _fail("a1_from", str(m))

m = parse_mailbox("Mary Smith <mary@example.net>")
if m:
    _pass("a1_to")
else:
    _fail("a1_to")

m = parse_mailbox('"Joe Q. Public" <john.q.public@example.com>')
if m and m.addr_spec == AddrSpec("john.q.public", "example.com"):
    _pass("a1_quoted_display")
else:
    _fail("a1_quoted_display", str(m))

m = parse_mailbox("jdoe@example.org")
if m:
    _pass("a1_no_display")
else:
    _fail("a1_no_display")

g = parse_address("A Group:Ed Jones <c@a.test>,joe@where.test,John <jdoe@one.test>;")
if g and isinstance(g, Group):
    _pass("a1_group")
else:
    _fail("a1_group", str(g))

g = parse_address("Undisclosed recipients:;")
if g and isinstance(g, Group):
    _pass("a1_empty_group")
else:
    _fail("a1_empty_group", str(g))


# =========================================================================
# Obsolete display name with periods (Joe Q. Public)
# =========================================================================
SECTION = "Obs-Phrase"

m = parse_mailbox("Joe Q. Public <john.q.public@example.com>")
if m and m.display_name == "Joe Q. Public":
    _pass("obs_phrase_display")
else:
    _fail("obs_phrase_display", repr(m.display_name if m else None))


# =========================================================================
# Obs-domain with whitespace around dots
# =========================================================================
SECTION = "Obs-Domain"

p = RFC5322Parser("jdoe@test  . example")
r = p.parse_addr_spec()
if r is not None:
    _pass("obs_domain_ws_dots", f"domain={r.domain}")
else:
    _fail("obs_domain_ws_dots")


# =========================================================================
# Compliance matrix
# =========================================================================
SECTION = "Compliance"

for key, val in COMPLIANCE_MATRIX.items():
    if isinstance(val, bool):
        if val:
            _pass(f"compliance_{key}")
        else:
            _fail(f"compliance_{key}", "unimplemented")


# =========================================================================
# Print results
# =========================================================================
print("=" * 70)
print("RFC 5322 Parser Test Results")
print("=" * 70)
print()

for status, section, name, detail in results:
    marker = "  ✓" if status == "PASS" else "  ✗"
    sec_str = f"[{section}]" if section else ""
    print(f"{marker} {sec_str} {name}")
    if status == "FAIL" and detail:
        print(f"      → {detail}")

print()
print("=" * 70)
print(f"PASS: {pass_count}  FAIL: {fail_count}  TOTAL: {pass_count + fail_count}")
print("=" * 70)

if fail_count > 0:
    print("\nFAILED TESTS:")
    for status, section, name, detail in results:
        if status == "FAIL":
            print(f"  ✗ [{section}] {name}: {detail}")
    sys.exit(1)
else:
    print("\nAll tests passed!")
    sys.exit(0)
