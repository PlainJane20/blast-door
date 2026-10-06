# Competency map

Each entry names the code or test that demonstrates it. Nothing here is claimed without evidence in the repository, and the environment is simulated.

## Systems design under uncertainty

**Behavior:** Decide what an autonomous agent may do when its planner is untrusted and its process can die at any moment.

**Evidence:**
- Model proposes, verifier decides ([ADR 001](adr/001-model-proposes-verifier-decides.md)); `test_scripted_planner_cannot_force_destructive_step`.
- Re-verify against the live world before every write; `test_environment_drift_between_plan_and_execute_is_blocked`, `test_freeze_starting_after_approval_blocks_execution`.
- Fail-stop on deny, tamper or drift; `test_denied_run_halts_and_skips_the_rest`.

## Durable execution and fault injection

**Behavior:** Make a long-running agent loop crash-safe, and prove it rather than assert it.

**Evidence:**
- One SQLite transaction per transition (state, checkpoint, audit); `executor.py`, `store.py`.
- Idempotency key per write enforced by the effects ledger; `test_crash_after_effect_is_recovered_from_ledger_not_replayed`.
- Kill at every step and phase boundary with `os._exit(137)`; `test_kill_point_resumes_to_identical_state` (in-process, 30 cases), `test_real_process_kill_then_resume` (real subprocess), `evals/crash_matrix.py`.
- Negative control: the detector fails when idempotency is off; `test_without_idempotency_a_crash_after_effect_double_executes`.

## Risk and governance

**Behavior:** Turn policy into enforced controls rather than documentation.

**Evidence:**
- Blast radius computed from a dry-run, including transitive dependents; `verifier.py`, `test_dry_run_includes_transitive_dependents`.
- Protected resources, change freeze, write budget, allowlist, scale-to-zero; `tests/test_verifier.py`.
- Single-use, expiring, plan-bound, no-self-approval approvals; `tests/test_approvals.py`.
- Unknown tools denied; param schemas strict; `tests/test_tools.py`.

## Auditability

**Behavior:** Make every decision reviewable after the fact.

**Evidence:**
- Hash-chained audit log in the same transaction as the transition; `test_audit_record_rolls_back_with_its_transaction`, `test_full_flow_audits_every_stage`.
- Append-only triggers, and tamper detection when they are bypassed; `test_edit_after_dropping_trigger_is_detected`, `test_ledger_rejects_update_and_delete`.
- `verify-audit` CLI command; `test_verify_audit_detects_tampering`.

## Observability

**Behavior:** Instrument the agent loop without coupling it to a vendor.

**Evidence:**
- OpenTelemetry spans for run, step, dry_run, verify, approval_wait, execute and resume, with run id, step id, verdict and blast radius; `tests/test_tracing.py`.
- No-op by default; only `opentelemetry-api` is a runtime dependency; `test_tracing_is_noop_by_default`.

## Measurement discipline

**Behavior:** Report what a number measures, and what it excludes.

**Evidence:**
- Eval catch rate is reported with a separate "right reason" rate, and sensitivity mutants show the corpus can fail (`evals/unsafe_corpus.py`, `test_eval_detects_a_verifier_that_allows_everything`).
- Authorship bias is stated next to the corpus numbers; latency caveats are stored in the JSON next to the figures (`evals/latency.py`).
- Environment is labeled SIMULATED in every eval output.

## Not demonstrated

- Any real infrastructure, Kubernetes, or cloud API.
- A live LLM planner, or confidence-based escalation.
- Multi-writer or multi-host coordination.
