"""Runtime paths shared by the main window and the VNC viewer."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


LEGACY_LOG_NAMES = ("ssh-session.log", "vnc-session.log")
INTERACTION_MARKERS = (
    "交互响应已提交",
    "interactive response submitted",
)


def application_directory() -> Path:
    """Return the directory containing the app, or the source project root."""
    if getattr(sys, "frozen", False):
        directory = Path(sys.executable).resolve().parent
        if directory.name.casefold() == "release":
            return directory.parent
        return directory
    return Path(__file__).resolve().parent


def application_logs_directory() -> Path:
    """Keep runtime logs in the project/app directory instead of AppData."""
    return application_directory() / "logs"


def _sanitize_legacy_chunk(name: str, data: bytes, redact_next: bool) -> tuple[bytes, bool]:
    """Remove old SSH prompt responses that earlier builds may have logged."""
    if name != "ssh-session.log":
        return data, redact_next

    lines = data.decode("utf-8", "replace").splitlines(keepends=True)
    sanitized: list[str] = []
    for line in lines:
        if redact_next:
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            prefix_match = re.match(r"^(\[[^\]]+\](?:\s+\[[^\]]+\])?)", line)
            prefix = prefix_match.group(1) if prefix_match else ""
            sanitized.append(f"{prefix} [历史交互内容已脱敏]{ending}")
            redact_next = False
            continue

        sanitized.append(line)
        lowered = line.casefold()
        if any(marker.casefold() in lowered for marker in INTERACTION_MARKERS):
            redact_next = True

    return "".join(sanitized).encode("utf-8"), redact_next


def migrate_legacy_logs() -> None:
    """Copy old AppData logs here and import any later lines on next launch."""
    destination = application_logs_directory()
    legacy = Path(os.environ.get("APPDATA") or Path.home()) / "VncTunnelManager" / "logs"
    if legacy.resolve() == destination.resolve():
        return

    try:
        destination.mkdir(parents=True, exist_ok=True)
        state_path = destination / ".legacy-log-migration.json"
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                state = {}
        except (OSError, json.JSONDecodeError):
            state = {}

        changed = False
        redact_next = bool(state.get("_redact_next_ssh_line", False))
        for name in LEGACY_LOG_NAMES:
            source = legacy / name
            target = destination / name
            try:
                source_size = source.stat().st_size
            except OSError:
                continue

            try:
                offset = max(0, int(state.get(name, 0)))
            except (TypeError, ValueError):
                offset = 0
            if source_size < offset:
                # The legacy log may have been removed and recreated by an old build.
                offset = 0
                if name == "ssh-session.log":
                    redact_next = False

            # Recognize files copied before the first new-version launch.
            if name not in state and target.is_file():
                target_size = target.stat().st_size
                prefix_size = min(source_size, target_size)
                with source.open("rb") as stream:
                    source_prefix = stream.read(prefix_size)
                with target.open("rb") as stream:
                    target_prefix = stream.read(prefix_size)
                if source_prefix == target_prefix:
                    offset = prefix_size

            if offset >= source_size:
                if name not in state:
                    state[name] = source_size
                    changed = True
                continue

            with source.open("rb") as stream:
                stream.seek(offset)
                new_bytes = stream.read()
            if not new_bytes:
                continue
            source_bytes_read = len(new_bytes)
            new_bytes, redact_next = _sanitize_legacy_chunk(name, new_bytes, redact_next)
            with target.open("ab") as stream:
                stream.write(new_bytes)
            state[name] = offset + source_bytes_read
            changed = True

        if redact_next != bool(state.get("_redact_next_ssh_line", False)):
            state["_redact_next_ssh_line"] = redact_next
            changed = True

        if changed:
            temporary_state = state_path.with_suffix(".tmp")
            temporary_state.write_text(
                json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_state.replace(state_path)
    except OSError:
        # Logging migration should never prevent the connection manager opening.
        return
