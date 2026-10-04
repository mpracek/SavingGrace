# ADR 005: Temporary disable
**Status**: Proposed (Phase 7)

**Decision**: Feature flag `temporaryDisableEnabled`; a typed challenge of `disableChallengeWordCount` words (default 50, range 10..100); time-limited; the agent owns the timer and the audit record. UI anti-paste/anti-drop is friction only; the agent enforces the state. Config validation for these keys and the `disable_audit` table already exist; no challenge logic does.

**Challenge text (changed from the original spec)**: the text to type is taken from the **Bible**, not from a Slovenian word list. It is selected locally from a bundled text, with no network access. The agent, not the UI, generates and verifies it so that the expected text is never trusted from the client.

**Open questions for Phase 7**
1. Translation and licence. A bundled text must be redistributable. The Dalmatin Bible (1584) is old enough to be public domain but is in archaic Slovenian; modern Slovenian translations are generally under copyright. English public-domain options exist (for example KJV). The choice, and whether the text follows the UI language, must be decided.
2. Selection rule. Proposed: a random consecutive passage of the configured length (so the user types real verses, not random words), avoiding passages with unusual characters.
3. Whether "word count" stays the unit (it does by default) and how verse numbers, punctuation and diacritics are treated when comparing.
