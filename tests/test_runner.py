"""Runner tests: scripted fake client, no network, real subprocess world stub.

world.py / verify.py / scenario.py may not be merged yet, so these tests
drive run_one through its injection seams with a contract-shaped stub world
(which really executes commands) and a stub scorer. The final test runs the
real SilentFailureDevops stack and auto-activates once those modules land.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from tribunal.events import EventLog, verify_chain
from tribunal.run import MAX_TURNS, PROTOCOL_ERROR_MSG, run_many, run_one

TRUNCATE = 4000


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class FakeClient:
    """Scripted replies; records every messages list it was called with."""

    def __init__(self, replies: list[str], model: str = "fake-model") -> None:
        self.model = model
        self._replies = list(replies)
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages: list[dict[str, str]]) -> str:
        self.calls.append([dict(m) for m in messages])
        return self._replies.pop(0)


class StubScenario:
    """Minimal Scenario-protocol implementation for driving the runner."""

    id = "stub"
    system_prompt = "Reply with RUN: <cmd> or CLAIM lines + DONE."
    tracked_paths = ["data.txt"]
    gt_probe_cmd = "grep -q done data.txt"

    def generate(self, seed: int) -> dict[str, str]:
        return {"data.txt": f"seed={seed}\n"}

    def pristine(self, seed: int) -> dict[str, str]:
        return {path: _sha256(content) for path, content in self.generate(seed).items()}

    def spec(self, seed: int) -> dict[str, Any]:
        return {
            "steps": [{"id": "s1", "weight": 1.0, "check": {"kind": "gt_probe_pass"}}],
            "traps": [],
        }


class StubWorld:
    """Contract-shaped world: really executes commands, logs the real results."""

    def __init__(self, scenario: StubScenario, seed: int, log: EventLog, workdir: Path) -> None:
        self.scenario = scenario
        self.seed = seed
        self.log = log
        self.workdir = workdir

    def setup(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        for path, content in self.scenario.generate(self.seed).items():
            (self.workdir / path).write_text(content, encoding="utf-8")

    def _run(self, cmd: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd, shell=True, cwd=self.workdir, capture_output=True, text=True, timeout=30
        )

    def step(self, cmd: str, turn: int) -> str:
        self.log.append("command", {"turn": turn, "cmd": cmd})
        start = time.monotonic()
        proc = self._run(cmd)
        self.log.append(
            "command_result",
            {
                "turn": turn,
                "exit_code": proc.returncode,
                "duration_ms": int((time.monotonic() - start) * 1000),
                "stdout": proc.stdout[:TRUNCATE],
                "stderr": proc.stderr[:TRUNCATE],
                "stdout_sha256": _sha256(proc.stdout),
                "stderr_sha256": _sha256(proc.stderr),
            },
        )
        for path in self.scenario.tracked_paths:
            file = self.workdir / path
            exists = file.exists()
            self.log.append(
                "file_state",
                {
                    "turn": turn,
                    "path": path,
                    "exists": exists,
                    "sha256": hashlib.sha256(file.read_bytes()).hexdigest() if exists else None,
                },
            )
        return f"exit_code={proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"

    def teardown(self) -> None:
        proc = self._run(self.scenario.gt_probe_cmd)
        self.log.append(
            "gt_probe",
            {
                "exit_code": proc.returncode,
                "stdout": proc.stdout[:TRUNCATE],
                "cmd": self.scenario.gt_probe_cmd,
            },
        )


class StubReport(BaseModel):
    run_id: str
    scenario_id: str
    chain_valid: bool
    capability: dict[str, float]
    silent_failure: dict[str, bool]
    adversarial: dict[str, bool]
    verdict: str


def stub_scorer(log_path: Path) -> StubReport:
    chain = verify_chain(log_path)
    return StubReport(
        run_id="stub-run",
        scenario_id="stub",
        chain_valid=chain.valid,
        capability={"score": 1.0},
        silent_failure={"flagged": False},
        adversarial={"honeypot_taken": False},
        verdict="competent",
    )


def make_world_factory(workdir: Path) -> Any:
    def factory(scenario: Any, seed: int, log: EventLog) -> StubWorld:
        return StubWorld(scenario, seed, log, workdir)

    return factory


def event_types(log_path: Path) -> list[str]:
    lines = log_path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line)["type"] for line in lines if line.strip()]


def log_path_for(report_path: Path) -> Path:
    return Path(str(report_path).removesuffix(".report.json") + ".jsonl")


def test_run_one_happy_path(tmp_path: Path) -> None:
    replies = [
        "RUN: cat data.txt",
        "RUN: echo done >> data.txt",
        "CLAIM: step s1 complete\nCLAIM: task complete\nDONE",
    ]
    client = FakeClient(replies)
    report_path = run_one(
        StubScenario(),
        42,
        client,
        tmp_path / "reports",
        world_factory=make_world_factory(tmp_path / "world"),
        scorer=stub_scorer,
    )

    log_path = log_path_for(report_path)
    assert log_path.name == "stub_42_fake-model.jsonl"
    result = verify_chain(log_path)
    assert result.valid and result.first_bad_idx is None

    types = event_types(log_path)
    assert types[0] == "run_meta"
    for required in ("agent_message", "command", "command_result", "file_state", "gt_probe"):
        assert required in types
    assert types[-1] == "run_end"

    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    run_end = events[-1]["data"]
    assert run_end == {"turns": 3, "reason": "done"}
    # gt_probe logged before run_end, and it really ran: "done" was appended.
    assert events[-2]["type"] == "gt_probe"
    assert events[-2]["data"]["exit_code"] == 0

    # Command output was fed back to the agent as the next user message.
    assert client.calls[1][-1]["role"] == "user"
    assert "seed=42" in client.calls[1][-1]["content"]

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_valid"] is True
    assert report["verdict"] == "competent"


def test_protocol_error_then_recovery(tmp_path: Path) -> None:
    replies = [
        "Let me think about what to do first.",
        "RUN: echo hi",
        "DONE",
    ]
    client = FakeClient(replies)
    report_path = run_one(
        StubScenario(),
        7,
        client,
        tmp_path / "reports",
        world_factory=make_world_factory(tmp_path / "world"),
        scorer=stub_scorer,
    )

    # Garbage reply drew the exact protocol-error user message.
    assert client.calls[1][-1] == {"role": "user", "content": PROTOCOL_ERROR_MSG}

    log_path = log_path_for(report_path)
    assert verify_chain(log_path).valid
    events = [json.loads(line) for line in log_path.read_text().splitlines()]
    commands = [e["data"] for e in events if e["type"] == "command"]
    assert commands == [{"turn": 2, "cmd": "echo hi"}]
    agent_turns = [e["data"]["turn"] for e in events if e["type"] == "agent_message"]
    assert agent_turns == [1, 2, 3]
    assert events[-1]["data"] == {"turns": 3, "reason": "done"}


def test_max_turns_reached(tmp_path: Path) -> None:
    client = FakeClient(["RUN: true"] * MAX_TURNS)
    report_path = run_one(
        StubScenario(),
        1,
        client,
        tmp_path / "reports",
        world_factory=make_world_factory(tmp_path / "world"),
        scorer=stub_scorer,
    )
    events = [json.loads(line) for line in log_path_for(report_path).read_text().splitlines()]
    assert events[-1]["data"] == {"turns": MAX_TURNS, "reason": "max_turns"}


def test_run_many_writes_aggregate(tmp_path: Path) -> None:
    replies_per_seed = ["RUN: echo done >> data.txt", "CLAIM: task complete\nDONE"]
    client = FakeClient(replies_per_seed * 2)
    aggregate_path = run_many(
        StubScenario(),
        [0, 1],
        client,
        tmp_path / "reports",
        world_factory=make_world_factory(tmp_path / "world"),
        scorer=stub_scorer,
    )
    aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    assert aggregate == {
        "model": "fake-model",
        "scenario_id": "stub",
        "n": 2,
        "mean_capability": 1.0,
        "silent_failure_rate": 0.0,
        "honeypot_rate": 0.0,
        "verdict_counts": {"competent": 2},
    }


def test_cli_schema_and_check_chain(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from tribunal.cli import main

    assert main(["schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert "oneOf" in schema["properties"]["data"]

    log = EventLog(tmp_path / "ok.jsonl")
    log.append("agent_message", {"turn": 1, "content": "hi"})
    log.close()
    assert main(["check-chain", str(tmp_path / "ok.jsonl")]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True

    bad = tmp_path / "bad.jsonl"
    bad.write_text((tmp_path / "ok.jsonl").read_text().replace('"hi"', '"ho"'))
    assert main(["check-chain", str(bad)]) == 1


def test_real_silent_failure_scenario_seed_42(tmp_path: Path) -> None:
    scenario_mod = pytest.importorskip("tribunal.scenario", reason="scenario.py not merged yet")
    pytest.importorskip("tribunal.world", reason="world.py not merged yet")
    pytest.importorskip("tribunal.verify", reason="verify.py not merged yet")
    scenario_cls = getattr(scenario_mod, "SilentFailureDevops", None)
    if scenario_cls is None:
        pytest.skip("SilentFailureDevops not defined yet")
    scenario = scenario_cls() if isinstance(scenario_cls, type) else scenario_cls

    replies = ["RUN: ls", "CLAIM: task complete\nDONE"]
    report_path = run_one(scenario, 42, FakeClient(replies), tmp_path / "reports")

    log_path = log_path_for(report_path)
    assert verify_chain(log_path).valid
    types = event_types(log_path)
    for required in (
        "run_meta",
        "agent_message",
        "command",
        "command_result",
        "gt_probe",
        "run_end",
    ):
        assert required in types
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["chain_valid"] is True
    assert report["verdict"] in {"competent", "silent_failure", "gaming", "incomplete"}
