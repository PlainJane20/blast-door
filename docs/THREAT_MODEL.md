# Threat model

Scope: what the verifier, the approval gate and the durable executor do and do **not** protect against. The environment is simulated, so every statement about "reality" below is a limit, not a result.

## Assets and actors

- **Asset:** the (simulated) infrastructure state, and the integrity of the record of what was done to it.
- **Planner** (rule-based, or a stand-in for a model): untrusted. It may propose anything.
- **Requester:** the operator who starts a run. Trusted to ask, not trusted to approve their own request.
- **Approver:** a different authenticated operator.
- **Verifier, executor, store:** trusted code running with access to the files.

## What is protected, and by what

| Threat | Control | Evidence |
|---|---|---|
| Planner proposes an unknown tool, bad params, or something destructive | Registry denies unknown tools; strict param schemas; verifier computes blast radius from the dry-run, not from the proposal | `test_scripted_unsafe_proposals_overridden`, corpus categories `unknown_tool`, `param_schema`, `scripted_destructive` |
| Blast radius larger than it looks (transitive dependents) | Dry-run returns dependents; limits apply to the full set | `test_dry_run_includes_transitive_dependents` |
| Touching a protected service | `needs_approval` or `deny` by policy | corpus category `protected` |
| Writing during a change freeze, including a freeze that starts after approval | Verified at plan time and again at execute time | `test_freeze_starting_after_approval_blocks_execution` |
| Requester approves their own request | Approver must differ from requester; both come from tokens | `test_self_approval_is_rejected_and_audited` |
| Reusing an approval (second use, other step, other run) | Single-use; bound to run, step and plan hash | `test_approval_is_consumed_exactly_once`, `test_approval_for_another_step_cannot_be_replayed` |
| Stale approval | Fixed expiry from request time; an expired approval is never spent | `test_approved_but_expired_before_use_is_not_executed_and_is_reissued` |
| Plan changed after approval | Approval is bound to a hash of tool, params and affected set; persisted plan is re-hashed before use | `test_tampered_plan_after_approval_is_blocked` |
| World changed after approval | Fresh dry-run must hash the same as the approved plan | `test_environment_drift_between_plan_and_execute_is_blocked` |
| Crash causes a repeated write | Idempotency key per write step, enforced by a UNIQUE column in the effects ledger | crash matrix; negative control shows a duplicate when keys are off |
| Silent edit of the audit history | Hash chain; verification reports the first bad record | `test_edit_after_dropping_trigger_is_detected` |

## What is NOT protected

1. **A compromised operator token.** Tokens are static shared secrets from an environment variable: no rotation, expiry, binding or TLS. Whoever holds a second operator's token can approve. Two colluding operators defeat the gate by design.
2. **A wrong blast-radius model.** The verifier is only as good as the dependency graph and the "protected" flags it is given. A missing edge means a missing dependent in the blast radius, and the verifier will confidently allow it. Determinism is not correctness.
3. **A simulated environment that differs from reality.** The dry-run runs against a model of infrastructure I wrote. A real `kubectl --dry-run=server` or cloud API can disagree (admission webhooks, quotas, controllers, eventual consistency). Nothing here has touched a real system. The real-adapter is Planned, not built.
4. **Anyone with write access to the database files.** They can drop the append-only triggers, rewrite the audit chain end to end, edit state, or insert an approval. The chain detects partial edits, not a full rewrite. Anchoring the chain head outside the host (a separate log service) is not built.
5. **The window between re-verify and write.** The executor re-checks immediately before writing, but a real system would need a server-side precondition (a resource version or compare-and-set). Here the window is tiny and simulated.
6. **Power loss and disk faults.** The crash tests kill the process with `os._exit(137)`. They do not test power loss, and on macOS SQLite's `fsync` does not flush the drive cache by default.
7. **Concurrent resumers.** There is no lease on a run. Two processes resuming the same run are not coordinated. The ledger's UNIQUE idempotency key still stops a duplicate write, but other races (duplicate approval requests, interleaved state saves) are not analyzed or tested.
8. **Clock tampering.** Freeze windows and approval expiry use the local clock.
9. **Semantic mistakes inside a valid action.** Restarting the wrong but valid, allowed, low-blast service passes every check. The verifier limits damage; it does not know intent.
10. **Reads.** Read tools are allowlist-checked only. There is no data-exfiltration control.
11. **A live LLM planner.** Not built, so prompt injection and model-specific failures are not exercised. The design assumption (the planner is untrusted) is tested only with a scripted stand-in.
12. **Corpus bias.** The unsafe corpus was written by the author who knew the rules. Catch rates measure that the rules behave as written.
