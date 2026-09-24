# Interpretation of Falco Events

Falco uses rules written in YAML to detect abnormal behaviour in containers
using kernel syscall data (via eBPF or kernel module).

## Event fields

- `evt.time` — event timestamp.
- `evt.type` — syscall type (execve, open, openat, connect, etc.).
- `proc.name` / `proc.cmdline` — process that made the call.
- `container.id` / `container.image.repository` — affected container.
- `user.name` / `user.uid` — user context of the action.

## Common important rules

- **Terminal shell in container** (`detect_shell_in_container`): a shell binary
  spawned in a pod, often a sign of container escape or a rogue process.
- **Read sensitive file trusted after startup**: unexpected read of
  `/etc/shadow`, kubelet credentials, or host files from inside a container.
- **Suspicious outbound connection**: connection to unexpected destinations.

## Responding

- Correlate with the orchestrator audit log and RBAC state.
- The AI agent collects Falco evidence, cross-references the audit log, and
  presents a security assessment. It may recommend monitoring / isolation but it
  must never delete data or restart pods on its own from a security alert.