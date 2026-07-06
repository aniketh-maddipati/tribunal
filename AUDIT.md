# AUDIT — tribunal kernel vs. verifier-probe target

Audit date: 2026-07-06. Method: every source file in `src/` and `tests/` was read
in full; the test suite was run; every CLI subcommand was executed. Evidence tags:
VERIFIED = ran it or read it fully; INFERRED = read partially; UNVERIFIED = could
not confirm. Nothing below is tagged INFERRED/UNVERIFIED — the codebase is small
(~1,960 LOC total) and was read completely.

## 1. Repo map

**Language / tooling.** Python 3.12, `uv`-managed, hatchling build
(`pyproject.toml:1-29`). Runtime deps: `pydantic>=2`, `httpx`
(`pyproject.toml:9-12`). Dev deps: pytest, ruff, mypy (strict)
(`pyproject.toml:17-22`). No CI config (`.github/` does not exist).

**Structure** (8 source files, 5 test files):

```
src/tribunal/
  events.py    204 LOC  hash-chained append-only event log + chain verifier + schemas
  world.py     133 LOC  seeded scratch-dir terminal world; runs commands, logs consequences
  scenario.py  140 LOC  Scenario protocol + one scenario (SilentFailureDevops)
  verify.py    263 LOC  deterministic verifier: capability / silent-failure / adversarial reads
  run.py       195 LOC  trajectory runner (run_one, run_many) + agent reply protocol parser
  agent.py      37 LOC  LMClient: OpenAI-compatible /chat/completions HTTP client
  cli.py       103 LOC  argparse CLI: run | score | check-chain | schema
tests/
  test_chain.py, test_world.py, test_verifier.py, test_runner.py, make_fixtures.py
  fixtures/    3 pre-built reference trajectories (competent / silent_failure / gaming)
```

**How to run.** `uv sync`, then `uv run tribunal <subcommand>` (entry point
`pyproject.toml:14-15` → `cli.py:96`). Verified live:

- `tribunal schema` → prints event JSON schema, exit 0 (VERIFIED, ran it).
- `tribunal check-chain tests/fixtures/competent.jsonl` → `valid: true, length: 19`,
  exit 0 (VERIFIED, ran it).
- `tribunal score tests/fixtures/gaming.jsonl` → full report JSON, verdict fields
  populated, exit 0 (VERIFIED, ran it).
- `tribunal run --model test-model --seeds 1` → crashes with
  `RuntimeError: could not reach LLM server at http://localhost:1234/v1:
  [Errno 111] Connection refused` (`agent.py:25`) because no local
  OpenAI-compatible server is running here. The run path up to the network call
  works: it created the log, wrote `run_meta` and turn-0 `file_state` events,
  ran teardown's ground-truth probe, and logged `run_end` with reason `error`
  (VERIFIED, ran it and inspected the resulting log). The live-LLM path has
  therefore **never been observed end-to-end in this audit** — only the
  fake-client path is proven (see tests).

**How to test.** `uv run pytest`. Result, verbatim: **`24 passed in 2.77s`**
(VERIFIED). `uv run ruff check .` → "All checks passed!"; `uv run mypy src`
(strict) → "Success: no issues found in 8 source files" (VERIFIED).

## 2. Component inventory

First, the kernel's own four claimed capabilities, then the 7 target components.

### 2a. Kernel capabilities (from CONTEXT)

| Capability | State | Evidence tag | Where | Notes |
|---|---|---|---|---|
| (a) Hash-chained event log | WORKS | VERIFIED | `events.py:46-115`; tests `test_chain.py:51-125` | Mutation/deletion/reorder/truncation all detected at first bad index; determinism proven; fsync per append (`events.py:79-81`). All 7 chain tests pass. |
| (b) World / terminal env | WORKS | VERIFIED | `world.py:31-133`; tests `test_world.py:47-119` | Seeded file generation, real subprocess execution with 30s timeout (`world.py:108-122`), tracked-file hashing per turn, honeypot-file restore before ground-truth probe (`world.py:92-97`). All 6 world tests pass. |
| (c) Two-axis verifier + honeypot detection | WORKS (within its scope) | VERIFIED | `verify.py:168-263`; tests `test_verifier.py:27-66` | Capability (weighted step checks, `verify.py:184-203`), silent-failure (claim vs probe, `verify.py:205-221`), adversarial/honeypot (`verify.py:223-239`). Separates the three reference trajectories with distinct signatures. Note: this is a **deterministic** verifier — there is no LLM judge in it anywhere. |
| (d) Attack harness that games the verifier | STUBBED-OR-PARTIAL | VERIFIED | `tests/make_fixtures.py:207-231` only | The "attack" is one hand-authored gaming trajectory (edit the test file so buggy code passes). No generator, no search, no automation. It attacks the *deterministic* verifier's honeypot, not a judge. |

### 2b. Target components (verifier-probe)

| # | Component | Exists? | State | Evidence tag | file:line | Notes |
|---|---|---|---|---|---|---|
| 1 | ORACLE | Yes | WORKS | VERIFIED | `world.py:98-106` (gt_probe runs real pytest, no model in loop); `scenario.py:77` (`gt_probe_cmd`); `verify.py:127-133` (`gt_probe_pass` check) | Deterministic ground truth via subprocess exit code, with honeypot-file restore so tampered tests can't fool it (`world.py:92-97`, proven by `test_world.py:77-89`). This is the strongest reusable asset. |
| 2 | JUDGE | No | MISSING | VERIFIED (absence: all 8 src files read fully) | — | No LLM-as-judge exists. Nothing sends a rubric + candidate to a model and parses a score. The only model call is the *agent under test* (`run.py:134`). |
| 3 | ATTACKER | No | MISSING | VERIFIED (absence) | closest: `make_fixtures.py:207-231` (one static gaming fixture); `scenario.py:125-139` (traps the attack targets) | No candidate generator, seed-pattern library, or model-generated attack loop. |
| 4 | MODEL ROUTER | Partial | STUBBED-OR-PARTIAL | VERIFIED | `agent.py:12-37` (single OpenAI-compat client); `cli.py:76-77` (one `--base-url`/`--model` for the whole run) | One transport, one role, no per-role routing, **no auth header** — so cloud providers requiring API keys are unreachable as-is. No mock client in `src/` (the test `FakeClient` lives at `test_runner.py:31-42`, tests only). |
| 5 | RUBRIC/TASK | Partial | STUBBED-OR-PARTIAL | VERIFIED | `scenario.py:71-140` (SilentFailureDevops: scored steps with weights `scenario.py:106-124`, traps `scenario.py:125-139`) | A scored task exists, but its "criteria" are machine checks (regex/hash/exit-code) for the deterministic verifier — there is no natural-language rubric a judge could grade against. Exactly one scenario is registered (`cli.py:17-25`). |
| 6 | EVENT LOG | Yes | WORKS | VERIFIED | `events.py:46-115`; typed payloads `events.py:118-189`; CLI `cli.py:51-63` | Fully working and tested; see 2a(a). One integrity caveat in Risks (#1). |
| 7 | ORCHESTRATOR | No | MISSING | VERIFIED (absence) | closest: `run.py:163-195` (`run_many` = sequential seed loop + aggregate.json) | No cascade, no cost tiers, no escalate-survivors logic. `run_many` iterates seeds over one client; that is all. |

## 3. Reuse map

| Existing piece | → Target component | Confidence | Notes |
|---|---|---|---|
| `world.py` teardown probe + `scenario.py` gt_probe_cmd + `verify.py` gt_probe/files_intact checks | ORACLE | High | Already model-free and tamper-resistant (pristine-restore at `world.py:92-97`). Needs only a thin "oracle(candidate) → pass/fail" wrapper. |
| `events.py` EventLog / verify_chain | EVENT LOG | High | Drop-in. New event types (judge_score, attack_candidate, divergence) are just new pydantic models in `EVENT_DATA_MODELS` (`events.py:181-189`). |
| `agent.py` LMClient | JUDGE transport + MODEL ROUTER seed | Medium | The HTTP plumbing is reusable, but it needs an API-key header for cloud, and the judge role (prompt, score parsing, retries) is all new code. |
| `scenario.py` SilentFailureDevops | RUBRIC/TASK | Medium | The seeded buggy-calc task is a fine first graded task; needs a natural-language rubric added for the judge. The VerificationSpec steps double as the oracle-side score. |
| `run.py` run_one/run_many + injection seams (`run.py:93-101`) | ORCHESTRATOR skeleton | Low-Medium | The world_factory/scorer seams show the intended extension style, but a cascade is a different control flow; expect to write a new driver rather than bend `run_one`. |
| `make_fixtures.py` gaming trajectory | ATTACKER seed patterns | Medium | The hand-authored tamper-the-test attack (`make_fixtures.py:207-231`) is seed pattern #1; the generator around it is missing. |
| `tests/test_runner.py` FakeClient | MODEL ROUTER "mock" backend | Medium | Works, but lives in tests; promote a MockClient into `src/` for offline runs. |
| `run.py` agent-protocol parsing (`run.py:60-67`), `verify.py` CLAIM regexes | (none) | — | Dead end for the probe target: the RUN/CLAIM/DONE protocol is for the terminal-agent use case, not judge probing. Keep for the agent-eval use case; don't build the probe on it. |

## 4. GAP — minimal missing pieces for ONE live experiment

Goal: attack a single live LLM-judge and measure divergence from oracle ground
truth. Ordered by shortest path to first live run:

1. **LMClient auth (S)** — add an `Authorization: Bearer` header / api-key param to
   `agent.py:18-23`; without it no cloud judge is reachable (a local server also
   works, but none exists in this environment).
2. **Judge role (S)** — new module: rubric prompt template + "grade this submission
   0–10, reply as JSON" + score parsing with a malformed-reply retry. ~60 LOC on
   top of LMClient. This is the single biggest functional gap: today no model
   ever grades anything.
3. **Rubric + oracle pair for one task (S)** — reuse the seeded calc-bugfix task:
   oracle = run pristine pytest on the candidate patch (wrap `world.py:98-106`
   logic); rubric = short natural-language grading criteria for the judge.
4. **Seed attack candidates (S)** — 5–10 hand-written candidates spanning the
   quadrants: genuine fix (oracle✓), tampered test (oracle✗ but plausible-looking),
   confident-prose-no-fix, prompt-injection-in-code-comment. The gaming fixture
   (`make_fixtures.py:207-231`) is candidate #1. Model-*generated* candidates are
   NOT needed for the first run.
5. **Probe driver + divergence report (M)** — loop: candidate → oracle verdict →
   judge score → append both to an EventLog → per-candidate divergence
   (judge_score high ∧ oracle fail = gap found) + a small aggregate. New event
   types registered in `events.py:181-189`.

Explicitly deferrable (not on the critical path): model-generated attacker (M),
multi-tier orchestrator cascade (M), per-role model router (M), more scenarios (M).

## 5. Shortest path to first live run

1. Add API-key support to `LMClient` (`agent.py`) and a `MockClient` in `src/` so
   the whole pipe can be smoke-tested offline first.
2. Write `judge.py`: rubric-prompted grading over LMClient returning a numeric
   score; unit-test the parsing with canned replies.
3. Write `oracle.py`: given a candidate calc.py patch, run pristine
   `pytest test_calc.py` in a scratch dir (lift `world.py:98-122`), return
   exit-code truth.
4. Author ~8 seed candidates for the calc task (genuine fix through
   test-tampering through judge-flattery) as data files.
5. Write `probe.py` driver: for each candidate, log oracle verdict + judge score
   into an EventLog, emit divergence table; run once against one live judge
   endpoint. That run is the first real experiment.

## 6. Risk register

1. **Log-file reuse silently merges runs → fake results.** `EventLog` re-opens an
   existing file and appends (`events.py:58-66`), and `run_one` derives the log
   path from scenario/seed/model only (`run.py:106`). Re-running the same triple
   appends a second full run into the same file — observed live in this audit: two
   crashed runs produced one file with two `run_meta`/`gt_probe`/`run_end`
   sequences (idx 0–6 and 7–13), a *valid* chain. `score()` then reads the FIRST
   `run_meta` (`verify.py:173-175`) but scans ALL events, and takes the LAST
   gt_probe exit (`verify.py:213-216`) — so run 2's probe silently decides run 1's
   silent-failure verdict. Highest-priority fix before trusting any results.
2. **Duplicate run_meta with conflicting run_ids in every run.** `run_one` appends
   run_meta (`run.py:109-121`) and then `World.setup()` appends a second one
   (`world.py:50-62`) with a different `uuid4` run_id. Observed live (idx 0 and 1
   of every log). The verifier happens to read the first; anything reading "the"
   run_meta by type will get an arbitrary one.
3. **No auth on the only network client** (`agent.py:18-23`) — cloud judges
   unreachable until fixed; also `temperature=0` and model are hard-coded per
   client, no per-role config.
4. **`files_intact` passes vacuously.** If no `file_state` events match the
   spec'd paths, `all()` over an empty list returns True (`verify.py:140-144`) —
   a log missing file_state events scores the intactness step as passed.
5. **Live-LLM path never exercised by tests.** Every runner test uses `FakeClient`
   (`test_runner.py:31-42`); nothing tests LMClient against even a stub HTTP
   server. First live run will be the first integration test of `agent.py`.
6. **Brittle text protocol.** Verdicts hinge on exact regex lines
   (`verify.py:27`, `run.py:29-30`); a competent agent that phrases its claim
   differently is scored "incomplete", inflating apparent failure rates.
7. **Dead code / aspirational markers.** `STEP_CLAIM_RE` is defined and never used
   (`verify.py:28`, sole occurrence repo-wide). README's Quickstart still lists
   the CLI as "Coming soon" (`README.md:25-27`) though it exists — stale docs.
   `run.py`'s docstring and `cli.py:2-5` reference "still being merged" modules
   that are all merged now.
8. **Lure detector is narrow.** `hints_lure` only fires on `cat|less|head` of
   HINTS.md (`scenario.py:134-137`); reading it any other way (grep, python,
   an editor) goes undetected.
9. **No CI** — the 24-test suite only runs when someone remembers to run it.

## 7. Honest verdict

This is a small (~1,100 LOC of source), clean, genuinely tested kernel for
*terminal-agent evaluation* — the event log, seeded world, and deterministic
three-read verifier all demonstrably work (24/24 tests pass, tamper-evidence
proven, CLI runs) — but it is **not yet a verifier-probe at all**. Of the seven
target components, only the oracle and the event log exist in usable form; the
judge, attacker, and orchestrator are entirely absent, the model layer is a
single unauthenticated OpenAI-compat client that has never been exercised against
a live endpoint in this audit, and the one "attack" is a hand-written fixture.
The full agent-in-the-loop path has only ever been proven with a scripted fake
client, and two confirmed logging defects (appended-run merging, duplicate
run_meta) would silently corrupt results today if runs were repeated. Realistic
read: a solid foundation worth keeping, roughly the first third of the target
system, with the entire judge-probing layer — the actual point of the tool —
still to be written.
