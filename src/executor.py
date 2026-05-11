"""A2A executor for the CyberGym purple agent.

Protocol (negotiated with the green agent):

  1. Green sends initial message: TextPart(prompt) + FilePart(README.md) +
     FilePart(repo-vul.tar.gz) + optional FilePart(description.txt),
     FilePart(error.txt), FilePart(repo-fix.tar.gz), FilePart(patch.diff).

  2. Purple analyses, asks the OpenAI reasoning model for a PoC-emitter script, runs it
     to produce raw PoC bytes.

  3. Purple OPTIONALLY tests the PoC by emitting a non-final
     TaskStatusUpdateEvent whose message carries
        DataPart({"action": "test_vulnerable"}) + FilePart(poc_bytes).
     Green runs the bytes against the vulnerable binary in docker and
     replies with a new user-message DataPart({"exit_code":..,"output":..}).

  4. Purple submits the final PoC as a TaskArtifactUpdateEvent with one
     FilePart (raw PoC bytes), then completes.

The handshake step means the executor receives TWO `execute()` calls for
the same task (initial + reply).  We keep per-task state in `self._sessions`
so the second call can hand the result back to the first call's worker
via an asyncio.Queue, and we use the FIRST call's event queue for the
final artifact (the green keeps that stream open).
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    Artifact,
    DataPart,
    FilePart,
    FileWithBytes,
    Message,
    Part,
    Role,
    TaskArtifactUpdateEvent,
    TaskState,
    TaskStatus,
    TaskStatusUpdateEvent,
    TextPart,
    UnsupportedOperationError,
)

from .analyzer import build_context
from .poc_generator import PoCGenerator, GenerationResult

logger = logging.getLogger(__name__)

MAX_TEST_ITERS = int(os.environ.get("MAX_TEST_ITERS", "1"))

TERMINAL_STATES = {
    TaskState.completed,
    TaskState.canceled,
    TaskState.failed,
    TaskState.rejected,
}


@dataclass
class Session:
    """Per-task state shared between the initial execute() and reply execute()s."""
    reply_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    done: asyncio.Event = field(default_factory=asyncio.Event)


def _extract_parts(message: Message) -> tuple[str, dict[str, bytes], dict[str, Any] | None]:
    """Return (text, {filename: bytes}, data_part_payload)."""
    text = ""
    files: dict[str, bytes] = {}
    data: dict[str, Any] | None = None
    for part in message.parts or []:
        root = part.root if hasattr(part, "root") else part
        if isinstance(root, TextPart):
            text += (root.text or "")
        elif isinstance(root, FilePart) and isinstance(root.file, FileWithBytes):
            name = root.file.name or f"file_{len(files)}"
            files[name] = base64.b64decode(root.file.bytes)
        elif isinstance(root, DataPart):
            data = root.data
    return text, files, data


class Executor(AgentExecutor):
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._generator = PoCGenerator()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        message = context.message
        if not message or not message.parts:
            logger.warning("Empty message received")
            return

        task = context.current_task
        if task and task.status.state in TERMINAL_STATES:
            return

        task_id = context.task_id or uuid4().hex
        context_id = context.context_id or task_id

        sess = self._sessions.get(context_id)
        # Distinguish initial green→purple message (has FilePart payload) from
        # the green's reply to a test_vulnerable handshake (DataPart only).
        text, files, data = _extract_parts(message)

        if sess is None:
            # First message in this context = run the full pipeline here.
            sess = Session()
            self._sessions[context_id] = sess
            try:
                await self._run_full_task(
                    event_queue=event_queue,
                    task_id=task_id,
                    context_id=context_id,
                    text=text,
                    files=files,
                    sess=sess,
                )
            finally:
                sess.done.set()
                self._sessions.pop(context_id, None)
            return

        # Continuation message — hand it to the in-flight worker.
        if data is not None:
            await sess.reply_queue.put(data)
        else:
            # Some clients may send the test result as a FilePart; in that
            # case just put a synthetic dict.
            await sess.reply_queue.put({"output": text, "files": list(files.keys())})

        # We still owe the client at least one event on this stream.
        await self._emit_status(
            event_queue, task_id, context_id,
            TaskState.working, "ack", final=True,
        )

    async def _run_full_task(
        self,
        *,
        event_queue: EventQueue,
        task_id: str,
        context_id: str,
        text: str,
        files: dict[str, bytes],
        sess: Session,
    ) -> None:
        await self._emit_status(
            event_queue, task_id, context_id,
            TaskState.working, "Analysing task files…", final=False,
        )

        # Infer task_id + level from the README the green attaches.
        cg_task_id, cg_level = _infer_task_meta(text, files)
        ctx = build_context(cg_task_id, cg_level, files)

        await self._emit_status(
            event_queue, task_id, context_id,
            TaskState.working,
            f"Generating PoC for {cg_task_id} (level={cg_level}, "
            f"crash={ctx.crash_type or '?'})…",
            final=False,
        )

        try:
            result: GenerationResult = await self._generator.generate(ctx)
        except Exception as e:
            logger.exception("Initial PoC generation failed")
            await self._emit_status(
                event_queue, task_id, context_id,
                TaskState.failed, f"PoC generation crashed: {e}", final=True,
            )
            return

        if not result.poc_bytes:
            # No PoC at all — submit a minimal placeholder so the run completes.
            await self._emit_status(
                event_queue, task_id, context_id,
                TaskState.working,
                f"Initial generation produced no bytes ({result.error[:200]}); "
                f"submitting empty PoC.",
                final=False,
            )
            await self._submit_artifact(event_queue, task_id, context_id, b"")
            await self._emit_status(
                event_queue, task_id, context_id,
                TaskState.completed, "done", final=True,
            )
            return

        prior_script = result.script
        poc = result.poc_bytes

        # Test/repair loop.
        for attempt in range(MAX_TEST_ITERS):
            feedback = await self._test_vulnerable(
                event_queue=event_queue,
                task_id=task_id,
                context_id=context_id,
                poc=poc,
                sess=sess,
            )
            if feedback is None:
                break  # green did not reply; just submit what we have

            output = (feedback.get("output") or "").lower()
            exit_code = feedback.get("exit_code")
            crashed = (
                exit_code not in (0, None)
                or "sanitizer" in output
                or "runtime error" in output
                or "segmentation" in output
                or "aborted" in output
            )
            if crashed:
                await self._emit_status(
                    event_queue, task_id, context_id,
                    TaskState.working,
                    f"PoC triggers vulnerable binary on attempt {attempt + 1} — "
                    f"keeping it.",
                    final=False,
                )
                break

            await self._emit_status(
                event_queue, task_id, context_id,
                TaskState.working,
                f"PoC did not trigger (attempt {attempt + 1}); requesting repair…",
                final=False,
            )
            try:
                repaired = await self._generator.repair(ctx, prior_script, poc, feedback)
            except Exception as e:
                logger.exception("Repair attempt failed")
                break
            if repaired.poc_bytes:
                poc = repaired.poc_bytes
                prior_script = repaired.script
            else:
                break  # no improvement; stop spending API calls

        await self._submit_artifact(event_queue, task_id, context_id, poc)
        await self._emit_status(
            event_queue, task_id, context_id,
            TaskState.completed, f"Submitted PoC ({len(poc)} bytes)", final=True,
        )

    # ------- message-emit helpers -------

    async def _emit_status(
        self,
        event_queue: EventQueue,
        task_id: str,
        context_id: str,
        state: TaskState,
        text: str,
        *,
        final: bool,
        extra_parts: list[Part] | None = None,
    ) -> None:
        parts: list[Part] = [Part(root=TextPart(kind="text", text=text))]
        if extra_parts:
            parts.extend(extra_parts)
        await event_queue.enqueue_event(
            TaskStatusUpdateEvent(
                taskId=task_id,
                contextId=context_id,
                status=TaskStatus(
                    state=state,
                    message=Message(
                        messageId=uuid4().hex,
                        role=Role.agent,
                        parts=parts,
                    ),
                ),
                final=final,
            )
        )

    async def _submit_artifact(
        self,
        event_queue: EventQueue,
        task_id: str,
        context_id: str,
        poc: bytes,
    ) -> None:
        await event_queue.enqueue_event(
            TaskArtifactUpdateEvent(
                taskId=task_id,
                contextId=context_id,
                artifact=Artifact(
                    artifactId=uuid4().hex,
                    name="poc",
                    parts=[Part(root=FilePart(
                        file=FileWithBytes(
                            bytes=base64.b64encode(poc).decode("ascii"),
                            name="poc",
                            mime_type="application/octet-stream",
                        ),
                    ))],
                ),
            )
        )

    async def _test_vulnerable(
        self,
        *,
        event_queue: EventQueue,
        task_id: str,
        context_id: str,
        poc: bytes,
        sess: Session,
    ) -> dict[str, Any] | None:
        """Ask the green to run the PoC against the vulnerable binary; await reply."""
        await self._emit_status(
            event_queue, task_id, context_id,
            TaskState.working, "Requesting test_vulnerable…",
            final=False,
            extra_parts=[
                Part(root=DataPart(data={"action": "test_vulnerable"})),
                Part(root=FilePart(
                    file=FileWithBytes(
                        bytes=base64.b64encode(poc).decode("ascii"),
                        name="poc",
                        mime_type="application/octet-stream",
                    ),
                )),
            ],
        )
        try:
            return await asyncio.wait_for(sess.reply_queue.get(), timeout=600)
        except asyncio.TimeoutError:
            logger.warning("test_vulnerable reply timed out")
            return None

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError(message="Cancellation not supported")


# --------- helpers ---------

def _infer_task_meta(text: str, files: dict[str, bytes]) -> tuple[str, str]:
    """Best-effort: figure out the task_id and level from greens' attachments.

    The green doesn't send task_id explicitly in the prompt, but we don't need
    it — analyzer.build_context is content-only.  Return harmless defaults so
    the prompt has a label.
    """
    task_id = "unknown"
    # Level is implied by which optional files are present.
    has_desc = "description.txt" in files
    has_err = "error.txt" in files
    has_patch = "patch.diff" in files
    has_fix = "repo-fix.tar.gz" in files
    if has_patch and has_fix:
        level = "level3"
    elif has_err and has_desc:
        level = "level2"
    elif has_desc:
        level = "level1"
    else:
        level = "level0"
    return task_id, level
