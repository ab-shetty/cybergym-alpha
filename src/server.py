"""A2A server entrypoint for the CyberGym purple agent."""
from __future__ import annotations

import argparse
import logging
import os

import uvicorn
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill

from .executor import Executor


def build_app(*, host: str, port: int, card_url: str | None = None):
    skill = AgentSkill(
        id="cybergym_poc_synth",
        name="CyberGym vulnerability PoC synthesiser",
        description=(
            "Receives a vulnerability description, error log, patch diff, and "
            "vulnerable source from the CyberGym green agent, and produces a "
            "proof-of-concept input that triggers the bug."
        ),
        tags=["cybersecurity", "vulnerability", "fuzzing", "poc"],
        examples=[
            "Generate a PoC for arvo:21578 given source + ASan log",
        ],
    )

    agent_card = AgentCard(
        name=f"CyberGym Purple Agent ({os.environ.get('OPENAI_MODEL', 'gpt-5-mini')})",
        description=(
            "PoC-synthesis agent for the CyberGym / Pi-Bench benchmark. "
            "Uses gpt-5-mini to reason over the description, sanitizer log, "
            "fix patch, and fuzz-harness source, then emits a PoC byte string "
            "and (optionally) iterates using the green's test_vulnerable "
            "feedback."
        ),
        url=card_url or f"http://{host}:{port}/",
        version="0.1.0",
        skills=[skill],
        default_input_modes=["text", "file"],
        default_output_modes=["text", "file"],
        capabilities=AgentCapabilities(streaming=True),
    )

    handler = DefaultRequestHandler(
        agent_executor=Executor(),
        task_store=InMemoryTaskStore(),
    )
    max_content_length = int(
        os.environ.get("A2A_MAX_CONTENT_LENGTH", str(256 * 1024 * 1024))
    )
    app = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=handler,
        max_content_length=max_content_length,
    )
    return app.build()


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberGym Purple Agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--card-url", default=None)
    args = parser.parse_args()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    uvicorn.run(
        build_app(host=args.host, port=args.port, card_url=args.card_url),
        host=args.host,
        port=args.port,
        timeout_keep_alive=3600,
    )


if __name__ == "__main__":
    main()
