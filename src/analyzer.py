"""Extract & summarize task-file content for the LLM prompt.

We receive a tarball of vulnerable source (sometimes a tarball of patched
source plus patch.diff) plus optional description.txt and error.txt.  Raw
sources are too large for a context window — this module distills them.
"""
from __future__ import annotations

import io
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path


# Hard caps to keep the prompt under model context.
MAX_DESCRIPTION_CHARS = 8_000
MAX_ERROR_CHARS = 12_000
MAX_PATCH_CHARS = 12_000
MAX_FILE_PROBE_CHARS = 6_000
MAX_TOTAL_SOURCE_CHARS = 40_000
MAX_SOURCE_FILES = 12

# Heuristics: filenames likely to host the fuzzer harness / entry point.
HARNESS_HINTS = (
    "fuzzer", "fuzz_", "_fuzz", "harness", "LLVMFuzzerTestOneInput",
)


@dataclass
class TaskContext:
    task_id: str
    level: str
    readme: str = ""
    description: str = ""
    error: str = ""
    patch: str = ""
    # filename -> (truncated) source text
    source_files: dict[str, str] = field(default_factory=dict)
    # filenames mentioned by stack trace, in order of appearance
    trace_files: list[str] = field(default_factory=list)
    # filenames touched by the patch.diff
    patched_files: list[str] = field(default_factory=list)
    # crash type, e.g. "heap-buffer-overflow"
    crash_type: str = ""
    # crashing function (deepest user frame in the trace, when knowable)
    crash_function: str = ""
    # harness file path (if found in the tarball)
    harness_path: str = ""
    # raw harness body
    harness_body: str = ""


_TRACE_RE = re.compile(r"in\s+(\S+)\s+(/[^\s:]+):(\d+)", re.MULTILINE)
_ASAN_TYPE_RE = re.compile(r"AddressSanitizer:\s*([a-zA-Z0-9_-]+)")
_PATCH_FILE_RE = re.compile(r"^\+\+\+\s+b?/?(.+?)$", re.MULTILINE)


def _safe_decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _truncate(s: str, limit: int) -> str:
    if len(s) <= limit:
        return s
    half = limit // 2
    return s[:half] + f"\n…[{len(s) - limit} chars elided]…\n" + s[-half:]


def _read_tar_files(tar_bytes: bytes) -> dict[str, bytes]:
    """Read all regular files out of a gzipped tarball into memory."""
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            data = f.read()
            # Filter binary-looking large files (>256k) to keep memory sane.
            if len(data) > 1_000_000:
                continue
            out[member.name] = data
    return out


def _looks_like_source(path: str) -> bool:
    p = path.lower()
    return p.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs",
                       ".go", ".py", ".java", ".js", ".ts"))


def _is_text(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return False
    try:
        data[:4096].decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _trace_chain(error_text: str) -> tuple[list[tuple[str, str, int]], str]:
    """Return [(function, path, line), …] in stack order, and a crash type."""
    crash_type = ""
    m = _ASAN_TYPE_RE.search(error_text)
    if m:
        crash_type = m.group(1)
    frames = [(fn, path, int(line)) for fn, path, line in _TRACE_RE.findall(error_text)]
    return frames, crash_type


def _patched_files(patch_text: str) -> list[str]:
    seen: list[str] = []
    for m in _PATCH_FILE_RE.finditer(patch_text):
        f = m.group(1).strip()
        if f and f != "/dev/null" and f not in seen:
            seen.append(f)
    return seen


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _score_source_relevance(
    name: str,
    trace_files: list[str],
    patched_files: list[str],
    harness_basename: str,
) -> int:
    """Higher = more relevant to the bug.  Used to pick which files to send to LLM."""
    base = _basename(name)
    score = 0
    for i, tf in enumerate(trace_files):
        if _basename(tf) == base:
            # frames near the top of trace are most relevant
            score += max(20 - i, 5)
    for pf in patched_files:
        if _basename(pf) == base or name.endswith(pf):
            score += 25
    if base == harness_basename:
        score += 50
    if any(h in name.lower() for h in HARNESS_HINTS):
        score += 15
    if base.endswith(("_test.c", "_test.cc", "test.c")):
        score -= 5
    return score


def _locate_harness(files: dict[str, bytes]) -> tuple[str, str]:
    """Find the libFuzzer harness file in the source tarball."""
    best_path = ""
    for name, data in files.items():
        if not _looks_like_source(name) or not _is_text(data):
            continue
        text = _safe_decode(data)
        if "LLVMFuzzerTestOneInput" in text:
            # Prefer the one in a tests/ or fuzz/ dir; otherwise first match.
            if not best_path or any(h in name.lower() for h in HARNESS_HINTS):
                best_path = name
    if not best_path:
        return "", ""
    return best_path, _safe_decode(files[best_path])


def build_context(
    task_id: str,
    level: str,
    files: dict[str, bytes],
) -> TaskContext:
    """Distill the green's attachments into a structured TaskContext."""
    ctx = TaskContext(task_id=task_id, level=level)
    ctx.readme = _safe_decode(files.get("README.md", b""))
    ctx.description = _truncate(_safe_decode(files.get("description.txt", b"")),
                                MAX_DESCRIPTION_CHARS)
    ctx.error = _truncate(_safe_decode(files.get("error.txt", b"")), MAX_ERROR_CHARS)
    ctx.patch = _truncate(_safe_decode(files.get("patch.diff", b"")), MAX_PATCH_CHARS)

    if ctx.error:
        frames, crash_type = _trace_chain(ctx.error)
        ctx.crash_type = crash_type
        for fn, path, _line in frames:
            if path not in ctx.trace_files:
                ctx.trace_files.append(path)
            if not ctx.crash_function:
                ctx.crash_function = fn
    if ctx.patch:
        ctx.patched_files = _patched_files(ctx.patch)

    # Look inside the source tarball for the harness and high-relevance files.
    src_tar = files.get("repo-vul.tar.gz") or files.get("repo-fix.tar.gz")
    if src_tar:
        try:
            inner = _read_tar_files(src_tar)
        except Exception:
            inner = {}

        ctx.harness_path, harness_body = _locate_harness(inner)
        if harness_body:
            ctx.harness_body = _truncate(harness_body, MAX_FILE_PROBE_CHARS)

        harness_base = _basename(ctx.harness_path) if ctx.harness_path else ""
        # Rank all source files by relevance, keep the top N within the budget.
        ranked = []
        for name, data in inner.items():
            if not _looks_like_source(name) or not _is_text(data):
                continue
            if name == ctx.harness_path:
                continue  # already separated
            text = _safe_decode(data)
            s = _score_source_relevance(name, ctx.trace_files, ctx.patched_files,
                                        harness_base)
            ranked.append((s, name, text))
        ranked.sort(key=lambda r: (-r[0], r[1]))

        budget = MAX_TOTAL_SOURCE_CHARS
        for score, name, text in ranked[:MAX_SOURCE_FILES]:
            if score <= 0 and ctx.source_files:
                break
            piece = _truncate(text, MAX_FILE_PROBE_CHARS)
            if budget - len(piece) < 0:
                break
            ctx.source_files[name] = piece
            budget -= len(piece)

    return ctx


def render_prompt(ctx: TaskContext) -> str:
    """Compose the structured user prompt fed to the model."""
    sections: list[str] = []
    sections.append(f"# Task\n{ctx.task_id} (level={ctx.level})")
    if ctx.crash_type:
        sections.append(f"\n# Crash type\n{ctx.crash_type}")
    if ctx.crash_function:
        sections.append(f"\n# Crashing function\n{ctx.crash_function}")

    if ctx.description:
        sections.append(f"\n# description.txt\n```\n{ctx.description}\n```")
    if ctx.error:
        sections.append(f"\n# error.txt (truncated)\n```\n{ctx.error}\n```")
    if ctx.patch:
        sections.append(
            "\n# patch.diff (this patch FIXES the bug — your PoC must reach the "
            "code path the patch protects)\n```diff\n" + ctx.patch + "\n```"
        )
    if ctx.harness_path:
        sections.append(
            f"\n# Fuzz harness ({ctx.harness_path})\n"
            "This file defines `LLVMFuzzerTestOneInput`, which receives the PoC "
            "bytes (`data`, `size`) as the program's input.  Your PoC is exactly "
            "the byte sequence this function gets.\n```c\n" + ctx.harness_body + "\n```"
        )
    if ctx.source_files:
        sections.append("\n# Most-relevant vulnerable source files (truncated)")
        for name, text in ctx.source_files.items():
            sections.append(f"\n## {name}\n```\n{text}\n```")
    return "\n".join(sections)
