"""Hash-chained event log: the tamper-evident receipts every verdict rests on.

Each log line is one EventEnvelope as canonical JSON. The envelope's hash is
the sha256 of the canonical JSON of the envelope *without* its hash field, and
each envelope's prev is the previous envelope's hash (genesis prev is 64
zeros). Any mutation, insertion, deletion, or reorder breaks the chain at the
first affected index; truncation yields a valid prefix, so a crashed run is
still verifiable up to its last fsynced event.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Literal, TextIO

from pydantic import BaseModel, ConfigDict, ValidationError

GENESIS_PREV = "0" * 64


def canonical_json(obj: Any) -> str:
    """Serialize to the exact canonical form the hash chain is computed over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idx: int
    ts: float
    prev: str
    type: str
    data: dict[str, Any]
    hash: str


def _compute_hash(idx: int, ts: float, prev: str, type: str, data: dict[str, Any]) -> str:
    body = {"idx": idx, "ts": ts, "prev": prev, "type": type, "data": data}
    return hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()


class EventLog:
    """Append-only JSONL writer that maintains the hash chain.

    Re-opening an existing log replays it to find the tip, so appends continue
    the chain rather than restarting it. Every append is flushed and fsynced
    before returning: a crash mid-run leaves a verifiable prefix on disk.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._next_idx = 0
        self._prev = GENESIS_PREV
        if self._path.exists():
            with self._path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    envelope = EventEnvelope.model_validate_json(line)
                    self._next_idx = envelope.idx + 1
                    self._prev = envelope.hash
        self._fh: TextIO = self._path.open("a", encoding="utf-8")

    def append(self, type: str, data: dict[str, Any], *, ts: float | None = None) -> EventEnvelope:
        timestamp = float(time.time() if ts is None else ts)
        digest = _compute_hash(self._next_idx, timestamp, self._prev, type, data)
        envelope = EventEnvelope(
            idx=self._next_idx,
            ts=timestamp,
            prev=self._prev,
            type=type,
            data=data,
            hash=digest,
        )
        self._fh.write(canonical_json(envelope.model_dump()) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._next_idx += 1
        self._prev = digest
        return envelope

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.close()


class ChainResult(BaseModel):
    valid: bool
    first_bad_idx: int | None
    length: int


def verify_chain(path: str | Path) -> ChainResult:
    """Recompute every hash and link; report the first index that fails."""
    lines = [ln for ln in Path(path).read_text(encoding="utf-8").splitlines() if ln.strip()]
    length = len(lines)
    prev = GENESIS_PREV
    for i, line in enumerate(lines):
        try:
            envelope = EventEnvelope.model_validate(json.loads(line))
        except (json.JSONDecodeError, ValidationError):
            return ChainResult(valid=False, first_bad_idx=i, length=length)
        if envelope.idx != i or envelope.prev != prev:
            return ChainResult(valid=False, first_bad_idx=i, length=length)
        recomputed = _compute_hash(
            envelope.idx, envelope.ts, envelope.prev, envelope.type, envelope.data
        )
        if recomputed != envelope.hash:
            return ChainResult(valid=False, first_bad_idx=i, length=length)
        prev = envelope.hash
    return ChainResult(valid=True, first_bad_idx=None, length=length)


class RunMetaData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    scenario_id: str
    seed: int
    model: str
    started_at: float
    tracked_paths: list[str]
    pristine: dict[str, str]
    spec: dict[str, Any]


class AgentMessageData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    turn: int
    content: str


class CommandData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    turn: int
    cmd: str


class CommandResultData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    turn: int
    exit_code: int
    duration_ms: int
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str


class FileStateData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    turn: int
    path: str
    exists: bool
    sha256: str | None


class GtProbeData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exit_code: int
    stdout: str
    cmd: str


class RunEndData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    turns: int
    reason: Literal["done", "max_turns", "error"]


EVENT_DATA_MODELS: dict[str, type[BaseModel]] = {
    "run_meta": RunMetaData,
    "agent_message": AgentMessageData,
    "command": CommandData,
    "command_result": CommandResultData,
    "file_state": FileStateData,
    "gt_probe": GtProbeData,
    "run_end": RunEndData,
}


def event_json_schema() -> dict[str, Any]:
    """JSON Schema for one log line: the envelope with data as a oneOf over
    the typed payload models."""
    schema = EventEnvelope.model_json_schema()
    defs: dict[str, Any] = schema.setdefault("$defs", {})
    one_of: list[dict[str, Any]] = []
    for model in EVENT_DATA_MODELS.values():
        payload = model.model_json_schema(ref_template="#/$defs/{model}")
        defs.update(payload.pop("$defs", {}))
        defs[model.__name__] = payload
        one_of.append({"$ref": f"#/$defs/{model.__name__}"})
    schema["properties"]["data"] = {"oneOf": one_of}
    return schema
