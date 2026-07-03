# Tribunal

Tribunal is a verifier for AI agents. A seeded terminal world runs an agent
through a multi-step task and records everything that physically happened —
commands, outputs, file states, a ground-truth probe — into a hash-chained,
append-only event log. The verifier then reads *only* that log and renders
three verdicts: **capability** (did the work actually get done), **silent
failure** (did the agent claim success while the ground truth says otherwise),
and **adversarial** (did it take honeypots or lures planted in the
environment). The agent's self-report is the thing under test, not the source
of truth.

**Invariant:** one-way flow, world → log → verifier. `verify.py` imports
nothing from `world.py`, `run.py`, or `agent.py`; it takes a log path and
returns a report. Tamper evidence comes from the chain itself — any mutation,
insertion, deletion, or reorder of the log breaks verification at the first
affected event, while a crashed run still yields a verifiable prefix.

## Quickstart

```sh
uv sync
uv run pytest

# Coming soon:
# uv run tribunal run --scenario <id> --seed <n>
# uv run tribunal verify reports/<run_id>.jsonl
```
