# Architecture

Everything runs against a **simulated** environment (SQLite-backed fake services, hosts and replicas). No real infrastructure is touched and no model is called.

## Flow of one write step

```mermaid
sequenceDiagram
    participant P as Planner (proposes only)
    participant X as Executor
    participant E as Simulated env
    participant V as Verifier (deterministic)
    participant A as Approvals
    participant H as Human (second person)
    participant S as SQLite store + audit chain

    X->>P: next_action(runbook, state)
    P-->>X: Proposal(step, tool, params)
    X->>S: checkpoint before_plan
    X->>E: dry_run=True (no state change)
    E-->>X: affected services + transitive dependents
    X->>S: commit plan + hash (after_plan)
    X->>V: verify(plan, policy, now, writes_so_far)
    V-->>X: Verdict allow / needs_approval / deny + reasons
    alt deny
        X->>S: step failed, run denied (nothing written)
    else needs_approval
        X->>A: request (bound to plan hash, TTL)
        X->>S: commit awaiting_approval (after_verdict)
        Note over X: process may exit here; the run is durable
        H->>A: approve(token) (not the requester)
        X->>A: consume (single use, plan hash must match)
    else allow
        X->>S: commit approved (after_verdict)
    end
    X->>E: dry-run again; hash must equal the approved plan
    X->>V: verify again against the world as it is now
    X->>S: checkpoint before_execute
    X->>E: write with idempotency key (ledger append, same txn)
    Note over X,E: crash point after_effect: effect landed, checkpoint not yet
    X->>S: commit executed (after_execute)
```

## Layers

| Layer | File | Responsibility |
|---|---|---|
| Models | `src/runbook_autopilot/models.py` | Pydantic v2 schemas; runbook validation (duplicate ids, unknown dependencies, cycles, unknown tools); plan hash |
| Simulated env | `sim_env.py` | Services, dependency edges, hosts, protected flag; read tools; write tools with `dry_run`; append-only effects ledger |
| Tools | `tools.py` | Registry: kind (read/write), strict param schema, blast-radius function per tool |
| Verifier | `verifier.py` | Policy (limits, protected handling, freeze windows, allowlist) to a Verdict with reasons. Pure function |
| Planner | `planner.py` | `Planner` protocol, `RuleBasedPlanner`, `ScriptedPlanner` test double. No live LLM planner |
| Executor | `executor.py` | Durable loop, crash points, idempotency keys, re-verify before write |
| Store | `store.py` | SQLite: runs, plans, approvals, checkpoints, audit. One transaction per transition |
| Approvals | `approvals.py`, `auth.py` | Single-use, expiring, plan-bound approvals; operator tokens to identity |
| Audit | `audit.py` | Hash-chained append-only log, written in the same transaction as the transition |
| Tracing | `tracing.py` | OpenTelemetry spans; no-op unless a provider is configured |
| CLI | `cli.py` | `run`, `status`, `approve`, `resume`, `verify-audit` |

## Step state machine

```
pending -> planned -> awaiting_approval -> approved -> executed
              |              |                |
              +--> approved -+ (allow)        +--> failed
              +--> failed (deny, tamper, drift, approval invalid)
any non-terminal step -> skipped (run halted, or never proposed)
```

Run status: `running`, `awaiting_approval`, `completed`, `failed`, `denied`. A denied or failed step halts the run (fail-stop); remaining steps become `skipped`.

## Crash points

`RUNBOOK_CRASH_AT=<step>:<phase>` (or `*:<phase>`) makes the process die with `os._exit(137)` at that boundary: no cleanup, no flush.

| Phase | State at the moment of the kill |
|---|---|
| `before_plan` | Intent checkpoint committed; nothing planned |
| `after_plan` | Plan, hash and dry-run committed |
| `after_verdict` | Verdict committed; approval requested or auto-approved |
| `before_execute` | Approved and re-verified; effect not applied |
| `after_effect` | **Effect applied (ledger row exists); executed checkpoint not written** |
| `after_execute` | Executed checkpoint committed |

`after_effect` is the dangerous one: the write is real but the executor does not know. On resume the executor looks the step's idempotency key up in the effects ledger, finds it, records `effect_found_in_ledger`, and moves on without writing again.

## Failure behavior

| Failure | Result |
|---|---|
| Process killed at any phase | `resume <run_id>` continues from the last committed checkpoint; no write is repeated |
| Unknown tool, bad params, failed dry-run | Verdict `deny`; step failed; run `denied` |
| Persisted plan edited after approval | Content hash no longer matches: step failed (`plan_tamper_detected`) |
| Environment changed between plan and execute | Fresh dry-run hash differs: step failed (`plan_drift`) |
| Policy violated at execute time (for example a freeze started) | Re-verify denies: step failed (`reverify_denied`) |
| Approval expired before use | Not spent; a new approval is requested; run stays `awaiting_approval` |
| Approval replayed or bound to another step or plan | Step failed (`approval_replayed` / `approval_invalid`) |
| No operator tokens configured | Nobody can authenticate, so nobody can approve (fail closed) |

## Why audit lives in the run database

edge-sentinel keeps its hash chain in a JSONL file. Here an audit record must be committed atomically with the state change it describes, or a kill between the two would leave a committed transition with no record (or a record for a transition that rolled back). Same SHA-256 chain, stored in a table inside the transition's transaction. SQLite triggers reject UPDATE and DELETE on the audit and ledger tables; anyone with file access can drop the triggers and rewrite the chain, so this is tamper-evident, not tamper-proof.
