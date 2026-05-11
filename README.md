# CyberGym Purple Agent (gpt-5-mini)

A2A purple agent for the [CyberGym / Pi-Bench](https://agentbeats.dev/agentbeater/cybergym)
benchmark.  Given a vulnerability description, sanitizer log, fix patch, and
the vulnerable source, the agent uses **gpt-5-mini** to emit a Python script
whose stdout is a proof-of-concept byte sequence that triggers the bug, then
hands the bytes back to the green agent as an A2A artifact.

## How it works

1. **Analyse** (`src/analyzer.py`).  Untars `repo-vul.tar.gz`, locates the
   `LLVMFuzzerTestOneInput` harness, parses the ASan stack trace, ranks the
   source files in the tarball by their distance to the crashing function and
   the lines touched by the patch.  Distills everything into a single
   structured prompt under ~80 KB.
2. **Generate** (`src/poc_generator.py`).  Asks gpt-5-mini for a self-contained
   Python emitter (`sys.stdout.buffer.write(b"…")`), executes it in a
   subprocess (20 s cap), and keeps the stdout bytes as the PoC.
3. **Test loop** (optional, `MAX_TEST_ITERS≥1`).  Sends the PoC back to the
   green via the `test_vulnerable` handshake; if the vulnerable binary exits
   cleanly, asks gpt-5-mini for a repaired emitter using the runner output as
   feedback.
4. **Submit**.  Final PoC is emitted as a `TaskArtifactUpdateEvent` with one
   `FilePart`.

## Repo layout

```
src/
  analyzer.py     - tar extraction, trace parsing, prompt builder
  poc_generator.py - LLM call + sandboxed script execution
  executor.py     - A2A executor with per-task session for the handshake
  server.py       - uvicorn entrypoint
scripts/
  local_eval.py   - download N tasks from HF and run end-to-end generation
Dockerfile
amber-manifest.json5
```

## Configuration (env vars)

| var | default | meaning |
|---|---|---|
| `OPENAI_API_KEY` | required | OpenAI key |
| `OPENAI_MODEL` | `gpt-5-mini` | reasoning model |
| `REASONING_EFFORT` | `medium` | initial draft |
| `MAX_TEST_ITERS` | `1` | round-trips with the green |
| `OPENAI_TIMEOUT_SEC` | `300` | per-call wall clock |
| `POC_SCRIPT_TIMEOUT_SEC` | `20` | per-emitter wall clock |

## Local dev

```bash
# Pin python 3.12
uv venv --python /usr/bin/python3.12 .venv
uv pip install --python .venv/bin/python \
  "a2a-sdk[http-server]>=0.3.20,<1.0" "openai>=1.50.0" "huggingface-hub>=0.24.0" \
  "httpx>=0.28.1" "pydantic>=2.10.0" "uvicorn>=0.30.0"

# Sanity-test on real HF tasks (no docker needed)
.venv/bin/python scripts/local_eval.py \
  --tasks arvo:21578 arvo:14529 arvo:3938 --level level3 --concurrency 3

# Stand up the A2A server
.venv/bin/python -m src.server --host 0.0.0.0 --port 8080
```

## Publishing

```bash
docker build -t ghcr.io/ab-shetty/cybergym-purple:latest .
docker push  ghcr.io/ab-shetty/cybergym-purple:latest
# Then update amber-manifest.json5 to point at the immutable @sha256:… digest.
```

## Notes / known limitations

- `gpt-5-mini` with `effort=medium` is ~10–60 s per task; occasional outliers
  hit several minutes.  The leaderboard scenario uses `num_workers: 10`, so
  this still fits under the per-shard CI budget.
- The local eval can't truly verify reproduction without docker — it only
  confirms that the pipeline yields a non-empty, well-formed PoC.
- The `test_vulnerable` round-trip only fires on the leaderboard runners
  (which run docker for the vulnerable image).
