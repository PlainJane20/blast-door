"""Static operator tokens -> identity (adapted from edge-sentinel/agent/auth.py).

    BLAST_DOOR_OPERATOR_TOKENS=alice:tokenA,bob:tokenB

These are shared secrets: no rotation, no expiry, no TLS. Unlike edge-sentinel
there is NO demo mode: with no tokens configured nobody can authenticate, so
nobody can approve anything (fail closed).
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass, field

ENV_TOKENS = "BLAST_DOOR_OPERATOR_TOKENS"


class AuthError(Exception):
    code = "unauthenticated"


@dataclass
class AuthConfig:
    operator_tokens: dict[str, str] = field(default_factory=dict)  # token -> identity

    @classmethod
    def from_string(cls, raw: str) -> "AuthConfig":
        operators: dict[str, str] = {}
        for pair in raw.split(","):
            pair = pair.strip()
            if not pair:
                continue
            name, sep, token = pair.partition(":")
            if not sep or not name.strip() or not token.strip():
                raise ValueError(f"{ENV_TOKENS} must look like alice:tokenA,bob:tokenB")
            operators[token.strip()] = name.strip()
        return cls(operators)

    @classmethod
    def from_env(cls, env=None) -> "AuthConfig":
        env = os.environ if env is None else env
        return cls.from_string(env.get(ENV_TOKENS, ""))

    def identify(self, token: str | None) -> str:
        """Constant-time lookup of a token. Raises AuthError if unknown."""
        if not token:
            raise AuthError("missing operator token")
        found = None
        for tok, name in self.operator_tokens.items():
            if hmac.compare_digest(token.encode(), tok.encode()):
                found = name
        if found is None:
            raise AuthError("invalid operator token")
        return found
