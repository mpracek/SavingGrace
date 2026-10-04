# ADR 004: Admin UI
**Status**: Proposed (Phase 6)

**Decision**: React + TypeScript in a lightweight desktop shell (Tauri candidate), talking to the agent over local IPC. Not started.

**Language**: the UI must let the user choose between **Slovenian and English**. All UI strings go through a translation layer with `sl` and `en` catalogs from the first screen onward (no hard-coded text), and a CI check must fail if a key exists in one catalog but not the other. The choice is persisted as the `uiLanguage` setting (`"sl"` or `"en"`, default `"sl"`), which is already validated in the configuration of both implementations and reported in the agent status. Whether the first-run default should follow the Windows display language is left open for Phase 6.

**Consequences**: The UI never enforces protection; closing it changes nothing.
