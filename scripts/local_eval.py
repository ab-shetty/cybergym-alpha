"""Local evaluation harness: download a small sample of CyberGym tasks
from HuggingFace, run our purple agent's PoC generation on each one
directly (no A2A round-trip), and report success rate + per-task latency.

Without docker we can't truly verify that the PoC triggers a sanitizer
crash — but we can at least confirm that:
  - the analyzer extracts a sensible context
  - gpt-5-mini returns parseable Python
  - the script executes inside the timeout and yields >0 bytes

Usage:
  uv run python scripts/local_eval.py \\
    --tasks arvo:21578 arvo:14529 arvo:34299 --level level3 --concurrency 3
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Make the `src` package importable when run as a script.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from huggingface_hub import hf_hub_download

from src.analyzer import build_context  # noqa: E402
from src.poc_generator import PoCGenerator  # noqa: E402


HF_DATASET = "sunblaze-ucb/cybergym"

LEVEL_FILES: dict[str, list[str]] = {
    "level0": ["repo-vul.tar.gz"],
    "level1": ["repo-vul.tar.gz", "description.txt"],
    "level2": ["repo-vul.tar.gz", "description.txt", "error.txt"],
    "level3": [
        "repo-vul.tar.gz",
        "repo-fix.tar.gz",
        "error.txt",
        "description.txt",
        "patch.diff",
    ],
}


def download_task(task_id: str, level: str) -> dict[str, bytes]:
    if ":" not in task_id:
        raise ValueError(f"bad task id {task_id!r}")
    category, num = task_id.split(":", 1)
    out: dict[str, bytes] = {}
    for fname in LEVEL_FILES[level]:
        hf_path = f"data/{category}/{num}/{fname}"
        local = hf_hub_download(repo_id=HF_DATASET, repo_type="dataset", filename=hf_path)
        out[fname] = Path(local).read_bytes()
    return out


async def evaluate_task(generator: PoCGenerator, task_id: str, level: str) -> dict:
    t0 = time.time()
    try:
        files = await asyncio.to_thread(download_task, task_id, level)
    except Exception as e:
        return {"task_id": task_id, "phase": "download", "error": str(e),
                "elapsed_s": time.time() - t0}

    ctx = build_context(task_id, level, files)
    t1 = time.time()
    try:
        res = await generator.generate(ctx)
    except Exception as e:
        return {"task_id": task_id, "phase": "generate", "error": str(e),
                "elapsed_s": time.time() - t0}

    return {
        "task_id": task_id,
        "level": level,
        "crash_type": ctx.crash_type,
        "crash_function": ctx.crash_function,
        "harness_path": ctx.harness_path,
        "n_source_files": len(ctx.source_files),
        "poc_bytes": len(res.poc_bytes or b""),
        "script_chars": len(res.script or ""),
        "script_error": (res.error or "")[:200],
        "download_s": round(t1 - t0, 1),
        "generate_s": round(time.time() - t1, 1),
        "total_s": round(time.time() - t0, 1),
    }


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tasks", nargs="+", required=True,
                        help="task ids like arvo:21578")
    parser.add_argument("--level", default="level3",
                        choices=list(LEVEL_FILES.keys()))
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--out", default=None,
                        help="optional JSON path to dump full results")
    args = parser.parse_args()

    if not os.environ.get("OPENAI_API_KEY"):
        sys.exit("OPENAI_API_KEY must be set")

    generator = PoCGenerator()
    sem = asyncio.Semaphore(args.concurrency)

    async def worker(tid: str) -> dict:
        async with sem:
            return await evaluate_task(generator, tid, args.level)

    results = await asyncio.gather(*(worker(t) for t in args.tasks))

    print(f"\n{'task':<22} {'crash':<22} {'poc_b':>6} {'gen_s':>6} {'note'}")
    print("-" * 80)
    n_ok = 0
    for r in results:
        ok = r.get("poc_bytes", 0) > 0 and not r.get("error")
        n_ok += int(ok)
        note = r.get("error") or r.get("script_error") or ("ok" if ok else "empty")
        print(f"{r.get('task_id',''):<22} {r.get('crash_type','')[:22]:<22} "
              f"{r.get('poc_bytes',0):>6} {r.get('generate_s',0):>6} {note[:30]}")
    print(f"\n{n_ok}/{len(results)} tasks produced non-empty PoCs")

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2))
        print(f"wrote full results to {args.out}")


if __name__ == "__main__":
    asyncio.run(main())
