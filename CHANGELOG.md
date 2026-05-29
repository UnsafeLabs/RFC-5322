# Changelog

All notable changes to the RFC-5322 parser project will be documented in this file.

## [1.0.0] - 2026-05-29

### Added
- **Parser Implementation (`parser.py`)**: Designed and implemented the `AddressParser` and `RFC5322Address` classes supporting RFC 5322 compliant address, mailbox, and group parsing, with options for strict and permissive modes.
- **Unit Test Suite (`test_parser.py`)**: Built a comprehensive suite of 70 tests mapping to sections §3.2.1 through §4.4, covering normal paths, edge cases (e.g., maximum length boundaries, deeply nested comments), and invalid rejection paths.
- **ABNF Compliance Matrix (`compliance.md`)**: Documented the mapping of all ABNF productions used in address parsing to their defining RFC sections and corresponding unit tests.
- **Project Documentation (`docs/gotchas.md`)**: Created documentation detailing the parser implementation architecture, CFWS comments recursion, obsolete syntax parsing patterns, and limitations.

### Changed
- **RFC Annotation (`source.md`)**: Populated all 4 `[CAP-ANNOTATION-REQUIRED]` markers with valid environment metrics under the SLSA Level 3 Contribution Annotation Protocol (CAP).
