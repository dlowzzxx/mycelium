"""Documented CLI commands and executable config examples stay in sync (#153).

Focused CI: pytest tests/test_doc_commands.py -v

Illustrative and NOT executed (networked/credentialed/provider-specific):
- sdk/examples/langgraph_redis_crash/mycelium.example.yaml (needs Redis + signing key)
- `mycelium demo --redis`, `verify --cluster`, live --redis-url/--postgres-dsn lines
- providers verify against live providers; webhook Stripe/GitHub/Twilio recipes
"""

# ruff: noqa: E501 - curated argv rows intentionally exceed 100 cols for readability

from __future__ import annotations

from pathlib import Path

from mycelium import load_config, load_config_from_string
from mycelium.cli.parser import build_parser
from mycelium.config_artifacts import render_config_example

SDK_ROOT = Path(__file__).resolve().parents[1]

# (docs location, argv without leading `mycelium`) — parse-only, no I/O or network.
DOCUMENTED = [
    ("Install", ["skills", "install"]), ("Install", ["init"]),
    ("Install", ["init", "--full"]), ("Install", ["init", "--minimal"]),
    ("Install", ["init", "--detect", "--project", "."]),
    ("Install", ["config", "schema"]), ("Install", ["config", "docs"]),
    ("Install", ["config", "example"]), ("Install", ["demo"]),
    ("migrate", ["migrate", "--plan", "--sqlite", "mycelium-ledger.db"]),
    ("migrate", ["migrate", "--apply", "--sqlite", "mycelium-ledger.db"]),
    ("doctor", ["doctor", "--config", "mycelium.yaml", "--strict", "--json"]),
    ("verify", ["verify", "--config", "mycelium.yaml", "--scenario", "all", "--strict", "--json"]),
    ("state", ["state", "migrate", "--plan", "--config", "mycelium.yaml"]),
    ("providers", ["providers", "verify", "gmail"]),
    ("transitions", ["transitions", "list", "--stuck", "--config", "mycelium.yaml"]),
    ("transitions", ["transitions", "show", "REQ", "--config", "mycelium.yaml"]),
    ("transitions", ["transitions", "release", "REQ", "--verified", "completed", "--by", "op", "--reason", "r", "--config", "mycelium.yaml"]),
    ("transitions", ["transitions", "mark-dead", "REQ", "--by", "op", "--reason", "r", "--config", "mycelium.yaml"]),
    ("transitions", ["transitions", "export", "--output", "o.ndjson", "--config", "mycelium.yaml"]),
    ("transitions", ["transitions", "prune", "--older-than", "30d", "--config", "mycelium.yaml"]),
    ("loops", ["loops", "status", "--stuck", "--config", "mycelium.yaml"]),
    ("loops", ["loops", "release", "RUN", "--verified", "clear", "--by", "op", "--reason", "r", "--config", "mycelium.yaml"]),
    ("budget", ["budget", "status", "--config", "mycelium.yaml"]),
    ("completion", ["completion", "status", "--config", "mycelium.yaml"]),
    ("completion", ["completion", "mark", "RUN", "sub", "--status", "success", "--config", "mycelium.yaml"]),
    ("scope", ["scope", "status", "--config", "mycelium.yaml"]),
    ("scope", ["scope", "bind", "RUN", "--config", "mycelium.yaml"]),
    ("outcomes", ["outcomes", "dttr", "--file", "o.jsonl"]),
    ("run", ["run", "--config", "mycelium.yaml", "--", "python", "-m", "my_agent"]),
]

EXAMPLES = [
    "mycelium/templates/mycelium.quickstart.yaml",
    "mycelium/templates/mycelium.minimal.yaml",
    "mycelium/templates/mycelium.template.yaml",
    "examples/mycelium.generated.example.yaml",
]


def test_documented_cli_commands_parse() -> None:
    parser = build_parser()
    for location, argv in DOCUMENTED:
        try:
            parser.parse_args(argv)
        except SystemExit as exc:
            cmd = "mycelium " + " ".join(argv)
            raise AssertionError(f"sdk/README.md:{location}: documented `{cmd}` no longer parses (exit {exc.code})") from exc


def test_checked_in_config_examples_validate() -> None:
    for relative in EXAMPLES:
        path = SDK_ROOT / relative
        try:
            load_config(path)
        except Exception as exc:
            raise AssertionError(f"{relative}: checked-in example fails schema validation: {exc}") from exc
    load_config_from_string(render_config_example())
