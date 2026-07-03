"""tribunal CLI: run trajectories, score logs, check chains, dump the schema.

Tribunal modules beyond stdlib/argparse are imported inside each subcommand so
`tribunal schema` (and check-chain) keep working even while scenario/world/
verify are still being merged.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_scenario(name: str) -> object:
    if name == "silent_failure":
        try:
            from tribunal.scenario import SilentFailureDevops
        except ImportError as exc:
            raise SystemExit(f"scenario module not available yet: {exc}") from exc
        if isinstance(SilentFailureDevops, type):
            return SilentFailureDevops()
        return SilentFailureDevops
    raise SystemExit(f"unknown scenario: {name!r} (available: silent_failure)")


def _cmd_run(args: argparse.Namespace) -> int:
    from tribunal.agent import LMClient
    from tribunal.run import run_many

    scenario = _load_scenario(args.scenario)
    client = LMClient(args.base_url, args.model)
    aggregate_path = run_many(scenario, range(args.seeds), client, Path(args.out))  # type: ignore[arg-type]
    print(aggregate_path.read_text(encoding="utf-8"))
    print(f"wrote {aggregate_path}", file=sys.stderr)
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    from tribunal.verify import score

    report = score(Path(args.log))
    text = report.model_dump_json(indent=2)
    print(text)
    if args.out is not None:
        Path(args.out).write_text(text, encoding="utf-8")
    return 0


def _cmd_check_chain(args: argparse.Namespace) -> int:
    from tribunal.events import verify_chain

    result = verify_chain(Path(args.log))
    print(result.model_dump_json(indent=2))
    return 0 if result.valid else 1


def _cmd_schema(args: argparse.Namespace) -> int:
    from tribunal.events import event_json_schema

    print(json.dumps(event_json_schema(), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tribunal",
        description="Verify AI agent trajectories from tamper-evident event logs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run an agent through a scenario across seeds")
    run_p.add_argument("--scenario", default="silent_failure")
    run_p.add_argument("--seeds", type=int, default=5, help="run seeds 0..N-1")
    run_p.add_argument("--base-url", default="http://localhost:1234/v1")
    run_p.add_argument("--model", required=True)
    run_p.add_argument("--out", default="reports/")
    run_p.set_defaults(func=_cmd_run)

    score_p = sub.add_parser("score", help="score a trajectory log, print report JSON")
    score_p.add_argument("log")
    score_p.add_argument("--out", default=None)
    score_p.set_defaults(func=_cmd_score)

    chain_p = sub.add_parser("check-chain", help="verify a log's hash chain")
    chain_p.add_argument("log")
    chain_p.set_defaults(func=_cmd_check_chain)

    schema_p = sub.add_parser("schema", help="print the event JSON schema")
    schema_p.set_defaults(func=_cmd_schema)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
