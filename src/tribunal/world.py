"""The seeded terminal world: executes commands and records what happened.

World never interprets agent text. It writes the scenario's files into a
scratch directory, runs whatever command it is handed, and logs the physical
consequences (command, result, tracked-file hashes) into the hash-chained
event log. At teardown it restores any honeypot-guarded files to their
generated content — so a tampered test file cannot fool the ground-truth
probe — then runs the probe and logs its outcome.
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from tribunal.events import EventLog
from tribunal.scenario import Scenario

TRUNCATE_CHARS = 4000
COMMAND_TIMEOUT_S = 30


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class World:
    def __init__(
        self, scenario: Scenario, seed: int, log: EventLog, *, model: str = "unknown"
    ) -> None:
        self.scenario = scenario
        self.seed = seed
        self.log = log
        self.model = model
        self.run_id = uuid.uuid4().hex
        self.scratch: Path | None = None

    def setup(self) -> None:
        """Create the scratch dir, write the seeded files, log run_meta and
        the initial (turn 0) file_state for every tracked path."""
        self.scratch = Path(tempfile.mkdtemp(prefix="tribunal-"))
        for rel_path, content in self.scenario.generate(self.seed).items():
            target = self.scratch / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        self.log.append(
            "run_meta",
            {
                "run_id": self.run_id,
                "scenario_id": self.scenario.id,
                "seed": self.seed,
                "model": self.model,
                "started_at": time.time(),
                "tracked_paths": list(self.scenario.tracked_paths),
                "pristine": self.scenario.pristine(self.seed),
                "spec": self.scenario.spec(self.seed),
            },
        )
        self._log_file_states(turn=0)

    def step(self, cmd: str, turn: int) -> str:
        """Execute cmd in the scratch dir; log command, command_result, and
        file_state for every tracked path; return the feedback text."""
        assert self.scratch is not None, "setup() must run before step()"
        self.log.append("command", {"turn": turn, "cmd": cmd})
        started = time.monotonic()
        exit_code, stdout, stderr = self._run(cmd)
        duration_ms = int((time.monotonic() - started) * 1000)
        self.log.append(
            "command_result",
            {
                "turn": turn,
                "exit_code": exit_code,
                "duration_ms": duration_ms,
                "stdout": stdout[:TRUNCATE_CHARS],
                "stderr": stderr[:TRUNCATE_CHARS],
                "stdout_sha256": _sha256_text(stdout),
                "stderr_sha256": _sha256_text(stderr),
            },
        )
        self._log_file_states(turn=turn)
        return f"exit={exit_code}\n{stdout}\n{stderr}"[:TRUNCATE_CHARS]

    def teardown(self) -> None:
        """Restore honeypot-guarded files to their generated content, then run
        the ground-truth probe and log it (run_end is the runner's job)."""
        assert self.scratch is not None, "setup() must run before teardown()"
        files = self.scenario.generate(self.seed)
        for trap in self.scenario.spec(self.seed).get("traps", []):
            detector = trap.get("detector", {})
            if detector.get("kind") == "file_modified" and detector.get("path") in files:
                path = detector["path"]
                (self.scratch / path).write_text(files[path], encoding="utf-8")
        exit_code, stdout, _stderr = self._run(self.scenario.gt_probe_cmd)
        self.log.append(
            "gt_probe",
            {
                "exit_code": exit_code,
                "stdout": stdout[:TRUNCATE_CHARS],
                "cmd": self.scenario.gt_probe_cmd,
            },
        )

    def _run(self, cmd: str) -> tuple[int, str, str]:
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=self.scratch,
                capture_output=True,
                timeout=COMMAND_TIMEOUT_S,
                text=True,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as exc:
            raw = exc.stdout
            captured = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            return 124, captured or "", "TIMEOUT"

    def _log_file_states(self, turn: int) -> None:
        assert self.scratch is not None
        for rel_path in self.scenario.tracked_paths:
            target = self.scratch / rel_path
            exists = target.is_file()
            sha = hashlib.sha256(target.read_bytes()).hexdigest() if exists else None
            self.log.append(
                "file_state",
                {"turn": turn, "path": rel_path, "exists": exists, "sha256": sha},
            )
