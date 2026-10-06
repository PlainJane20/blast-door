"""Human approval gate.

An approval is: single-use, expiring, bound to the hash of the exact plan,
requested by one identity and grantable only by a different authenticated one.
Identity comes from an operator token, never from a request field.
"""
from __future__ import annotations

import time

from .audit import AuditLog
from .auth import AuthConfig, AuthError
from .models import ApprovalRecord, ApprovalStatus, sha256
from .store import RunStore


class ApprovalError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class ApprovalService:
    def __init__(self, store: RunStore, audit: AuditLog, auth: AuthConfig, clock=time.time):
        self.store, self.audit, self.auth, self.clock = store, audit, auth, clock

    # -- creation (called by the executor inside its own transaction) ----------
    def create(self, c, run_id: str, step_id: str, plan_hash: str, requester: str,
               ttl_s: int) -> ApprovalRecord:
        attempt = self.store.count_approvals(c, run_id, step_id)
        now = self.clock()
        rec = ApprovalRecord(
            id="ap-" + sha256(f"{run_id}:{step_id}:{attempt}")[:10], run_id=run_id,
            step_id=step_id, plan_hash=plan_hash, requester=requester,
            created_at=now, expires_at=now + ttl_s)
        c.execute("INSERT INTO approvals(id, run_id, step_id, plan_hash, requester, status, "
                  "created_at, expires_at) VALUES (?,?,?,?,?,?,?,?)",
                  (rec.id, run_id, step_id, plan_hash, requester, rec.status.value,
                   rec.created_at, rec.expires_at))
        self.audit.append(c, "approval_requested", {
            "approval_id": rec.id, "run_id": run_id, "step_id": step_id,
            "plan_hash": plan_hash, "requester": requester, "expires_at": rec.expires_at})
        return rec

    # -- a human grants it -----------------------------------------------------
    def approve(self, approval_id: str, token: str | None) -> ApprovalRecord:
        try:
            approver = self.auth.identify(token)
        except AuthError as e:
            self.audit.append_now("approval_rejected", {
                "approval_id": approval_id, "code": e.code, "detail": str(e)})
            raise ApprovalError(e.code, str(e)) from None
        now = self.clock()
        err: ApprovalError | None = None
        with self.store.txn() as c:
            rec = self.store.get_approval(approval_id, c)
            if rec is None:
                err = ApprovalError("not_found", approval_id)
            elif rec.status != ApprovalStatus.pending:
                err = ApprovalError("not_pending", f"approval is {rec.status.value}")
            elif now > rec.expires_at:
                c.execute("UPDATE approvals SET status='expired' WHERE id=?", (approval_id,))
                err = ApprovalError("expired", "approval expired before it was granted")
            elif approver == rec.requester:
                err = ApprovalError("self_approval", f"{approver} cannot approve their own request")
            if err is not None:
                self.audit.append(c, "approval_rejected", {
                    "approval_id": approval_id, "approver": approver, "code": err.code})
            else:
                c.execute("UPDATE approvals SET status='approved', approver=?, approved_at=? "
                          "WHERE id=?", (approver, now, approval_id))
                self.audit.append(c, "approval_granted", {
                    "approval_id": approval_id, "approver": approver, "run_id": rec.run_id,
                    "step_id": rec.step_id, "plan_hash": rec.plan_hash})
        if err is not None:
            raise err
        return self.store.get_approval(approval_id)  # type: ignore[return-value]

    # -- the executor spends it ------------------------------------------------
    def consume(self, c, approval_id: str | None, run_id: str, step_id: str,
                plan_hash: str) -> tuple[str, str]:
        """Check and spend an approval inside the executor's transaction.

        Returns (outcome, detail). outcome is one of:
        ok, pending, expired, replayed, invalid.
        """
        if not approval_id:
            return "invalid", "step has no approval"
        rec = self.store.get_approval(approval_id, c)
        if rec is None:
            return "invalid", "approval not found"
        if rec.run_id != run_id or rec.step_id != step_id:
            return "invalid", "approval belongs to a different run or step"
        if rec.plan_hash != plan_hash:
            return "invalid", "plan changed since approval was requested"
        if rec.status == ApprovalStatus.consumed:
            return "replayed", "approval was already used"
        now = self.clock()
        if rec.status == ApprovalStatus.pending:
            if now > rec.expires_at:
                c.execute("UPDATE approvals SET status='expired' WHERE id=?", (rec.id,))
                return "expired", "approval expired while pending"
            return "pending", "waiting for a human"
        if rec.status == ApprovalStatus.expired or now > rec.expires_at:
            c.execute("UPDATE approvals SET status='expired' WHERE id=?", (rec.id,))
            return "expired", "approval expired before use"
        if rec.approver is None or rec.approver == rec.requester:
            return "invalid", "approver missing or equals requester"
        c.execute("UPDATE approvals SET status='consumed', consumed_at=? WHERE id=?", (now, rec.id))
        return "ok", rec.approver
