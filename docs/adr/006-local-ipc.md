# ADR 006: Local IPC and authorization
**Status**: Accepted for Phase 2 (read-only); authorization for mutating commands is OPEN

**Context**: The Admin UI and the CLI must query the service. The service runs as LocalSystem; the UI runs as the logged-in user.

**Decision**
- Transport: Windows named pipe `\\.\pipe\savinggrace-agent` (Unix socket on non-Windows dev hosts). Remote clients rejected. `first_pipe_instance(true)` so a process cannot squat the name before the service starts.
- Protocol: one JSON object per line, request `{"command": ...}`, response `{"ok", "result" | "error"}`. Frames over 8 KiB, unknown commands and malformed JSON are rejected with a structured error; max 16 concurrent connections; 30 s idle timeout.
- Commands in protocol v1 are **read-only**: `ping`, `get_status`, `check_domain` (evaluates a hostname, logs nothing).
- Because nothing can change state, the pipe uses the service account's default security descriptor and no caller authentication is performed.

**Open**: Phase 4 adds list editing and Phase 7 adds temporary disable. Before either ships, a caller-authorization model must be decided (for example restricting writes to members of Administrators via an explicit pipe DACL and token check). A standard user must not be able to disable protection or empty the blocklist over IPC. This ADR will be revised then.

**Consequences**: Any local user can read agent status and ask whether a hostname would be blocked. Neither reveals browsing history.
