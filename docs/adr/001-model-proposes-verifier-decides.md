# ADR 001: The model proposes, the verifier decides

## Status
Accepted

## Context
An autonomous loop that can restart services, scale them or drain hosts must not let its planner (a model, or anything standing in for one) widen its own permissions. Earlier projects in this portfolio gate agent actions with approvals; [edge-sentinel ADR 001](https://github.com/PlainJane20/edge-sentinel/blob/main/docs/adr/001-model-proposes-policy-decides.md) records the failures that motivated this rule: a model's own risk label deciding whether approval was needed, requesters approving their own actions, and approvals that nothing checked before executing. Here the risk is larger, because one proposed action can fan out to every service that depends on the target.

## Decision
- The planner returns a `Proposal` (step id, tool, params). It has no other channel into the system.
- Risk is never read from the proposal. It is computed from a **dry-run** against the environment: the exact set of affected resources, including transitive dependents.
- A pure, deterministic `Verifier` maps (plan, policy, now, writes so far) to `allow`, `needs_approval` or `deny`, with every reason. No LLM, no randomness, no I/O.
- Unknown tools and invalid params are denied. A tool absent from the allowlist is denied.
- `needs_approval` needs a different authenticated person; the approval is single-use, expires, and is bound to a hash of the exact plan.
- The verdict is recomputed immediately before the write, against the world as it is then. Any difference from the approved plan fails the step.
- Writes carry an idempotency key enforced by an append-only effects ledger, so resuming after a crash cannot repeat them.

## Consequences
- A planner that is wrong, hostile or hallucinating cannot execute anything the verifier denies; this is tested with a scripted "model" that proposes destructive steps.
- The system is only as safe as the blast-radius model: a missing dependency edge is a missing dependent. See `THREAT_MODEL.md`.
- Adding a tool means adding a registry entry (kind, param schema, blast function), a reviewable change.
- Rigidity is the cost: a genuinely new situation needs a policy or code change, not a better prompt.
- A future LLM planner can be added behind the same `Planner` protocol without changing any of the guarantees. It is not built.
