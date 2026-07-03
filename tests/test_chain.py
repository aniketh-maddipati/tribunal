"""Tamper-evidence tests for the hash-chained event log."""

from pathlib import Path

from tribunal.events import EventEnvelope, EventLog, event_json_schema, verify_chain

MIXED_EVENTS: list[tuple[str, dict[str, object]]] = [
    (
        "run_meta",
        {
            "run_id": "r-001",
            "scenario_id": "demo",
            "seed": 7,
            "model": "test-model",
            "started_at": 1000.0,
            "tracked_paths": ["data.csv"],
            "pristine": {"data.csv": "a" * 64},
            "spec": {"steps": [], "traps": []},
        },
    ),
    ("agent_message", {"turn": 1, "content": "RUN: cat data.csv"}),
    ("command", {"turn": 1, "cmd": "cat data.csv"}),
    (
        "command_result",
        {
            "turn": 1,
            "exit_code": 0,
            "duration_ms": 12,
            "stdout": "a,b\n1,2\n",
            "stderr": "",
            "stdout_sha256": "b" * 64,
            "stderr_sha256": "c" * 64,
        },
    ),
    ("file_state", {"turn": 1, "path": "data.csv", "exists": True, "sha256": "a" * 64}),
    ("agent_message", {"turn": 2, "content": "hello-5 marker"}),
    ("command", {"turn": 2, "cmd": "wc -l data.csv"}),
    ("file_state", {"turn": 2, "path": "data.csv", "exists": True, "sha256": "a" * 64}),
    ("gt_probe", {"exit_code": 0, "stdout": "ok\n", "cmd": "sh check.sh"}),
    ("run_end", {"turns": 2, "reason": "done"}),
]


def write_log(path: Path, events: list[tuple[str, dict[str, object]]]) -> list[EventEnvelope]:
    log = EventLog(path)
    envelopes = [log.append(t, dict(d), ts=1000.0 + i) for i, (t, d) in enumerate(events)]
    log.close()
    return envelopes


def test_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    # Split the appends across two EventLog instances to also prove that
    # re-opening an existing file replays it and continues the chain.
    write_log(path, MIXED_EVENTS[:6])
    log = EventLog(path)
    for i, (event_type, data) in enumerate(MIXED_EVENTS[6:], start=6):
        log.append(event_type, dict(data), ts=1000.0 + i)
    log.close()

    result = verify_chain(path)
    assert result.valid
    assert result.first_bad_idx is None
    assert result.length == 10


def test_mutation_detected(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_log(path, MIXED_EVENTS)

    lines = path.read_text().splitlines()
    assert "hello-5" in lines[5]
    lines[5] = lines[5].replace("hello-5", "hellx-5")
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.valid
    assert result.first_bad_idx == 5


def test_deletion_detected(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_log(path, MIXED_EVENTS)

    lines = path.read_text().splitlines()
    del lines[3]
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.valid
    assert result.first_bad_idx == 3


def test_reorder_detected(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_log(path, MIXED_EVENTS)

    lines = path.read_text().splitlines()
    lines[6], lines[7] = lines[7], lines[6]
    path.write_text("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result.valid
    assert result.first_bad_idx == 6


def test_truncation_is_valid_prefix(tmp_path: Path) -> None:
    path = tmp_path / "run.jsonl"
    write_log(path, MIXED_EVENTS)

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:4]) + "\n")

    result = verify_chain(path)
    assert result.valid
    assert result.first_bad_idx is None
    assert result.length == 4


def test_determinism(tmp_path: Path) -> None:
    envelopes_a = write_log(tmp_path / "a.jsonl", MIXED_EVENTS)
    envelopes_b = write_log(tmp_path / "b.jsonl", MIXED_EVENTS)

    assert [e.hash for e in envelopes_a] == [e.hash for e in envelopes_b]
    assert (tmp_path / "a.jsonl").read_text() == (tmp_path / "b.jsonl").read_text()


def test_event_json_schema_covers_all_payloads() -> None:
    schema = event_json_schema()
    one_of = schema["properties"]["data"]["oneOf"]
    refs = {ref["$ref"].rsplit("/", 1)[-1] for ref in one_of}
    assert len(one_of) == 7
    assert {"RunMetaData", "RunEndData", "GtProbeData"} <= refs
    assert set(schema["required"]) == {"idx", "ts", "prev", "type", "data", "hash"}
