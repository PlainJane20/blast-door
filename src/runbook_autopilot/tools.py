"""Tool registry. Each tool declares its kind, a param schema, and a blast-radius function.

Unknown tools are not in the registry, so the verifier denies them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import BlastRadius, DryRunResult, ToolKind
from .sim_env import SimEnv, WriteContext


class ParamsError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoParams(_Strict):
    pass


class ServiceParams(_Strict):
    service: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")


class MetricsParams(ServiceParams):
    pass


class ScaleParams(ServiceParams):
    replicas: int = Field(strict=True, ge=0, le=50)


class HostParams(_Strict):
    host: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")


BlastFn = Callable[[BaseModel, DryRunResult], BlastRadius]
InvokeFn = Callable[[SimEnv, BaseModel, bool, "WriteContext | None"], Any]


def standard_blast(params: BaseModel, dr: DryRunResult) -> BlastRadius:
    return BlastRadius(services=sorted(dr.affected_services), hosts=sorted(dr.affected_hosts),
                       protected=sorted(dr.protected), transitive=sorted(dr.transitive_dependents))


def scale_blast(params: BaseModel, dr: DryRunResult) -> BlastRadius:
    b = standard_blast(params, dr)
    if getattr(params, "replicas", None) == 0:
        b.flags.append("scale_to_zero")
    return b


def no_blast(params: BaseModel, dr: DryRunResult) -> BlastRadius:
    return BlastRadius()


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: ToolKind
    params_model: type[BaseModel]
    invoke: InvokeFn
    blast: BlastFn
    description: str = ""


def _read(fn: Callable[[SimEnv, BaseModel], Any]) -> InvokeFn:
    def run(env, p, dry_run, ctx):
        return fn(env, p)
    return run


class ToolRegistry:
    def __init__(self, specs: list[ToolSpec]):
        self._specs = {s.name: s for s in specs}

    def names(self) -> set[str]:
        return set(self._specs)

    def maybe(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def validate_params(self, name: str, params: dict) -> BaseModel:
        spec = self._specs[name]
        try:
            return spec.params_model.model_validate(params)
        except ValidationError as e:
            msg = "; ".join(f"{'.'.join(map(str, err['loc'])) or '<root>'}: {err['msg']}"
                            for err in e.errors())
            raise ParamsError(msg) from None

    @classmethod
    def default(cls) -> "ToolRegistry":
        return cls([
            ToolSpec("list_services", ToolKind.read, NoParams,
                     _read(lambda e, p: {"services": e.list_services()}), no_blast,
                     "List all services"),
            ToolSpec("get_service_status", ToolKind.read, ServiceParams,
                     _read(lambda e, p: e.get_service_status(p.service)), no_blast,
                     "Status of one service"),
            ToolSpec("get_metrics", ToolKind.read, MetricsParams,
                     _read(lambda e, p: e.get_metrics(p.service)), no_blast,
                     "Synthetic deterministic metrics"),
            ToolSpec("restart_service", ToolKind.write, ServiceParams,
                     lambda e, p, d, c: e.restart_service(p.service, dry_run=d, ctx=c),
                     standard_blast, "Restart one service (dependents are affected)"),
            ToolSpec("rollout_restart", ToolKind.write, ServiceParams,
                     lambda e, p, d, c: e.rollout_restart(p.service, dry_run=d, ctx=c),
                     standard_blast, "Rolling restart of one service"),
            ToolSpec("scale_service", ToolKind.write, ScaleParams,
                     lambda e, p, d, c: e.scale_service(p.service, p.replicas, dry_run=d, ctx=c),
                     scale_blast, "Set replica count"),
            ToolSpec("drain_host", ToolKind.write, HostParams,
                     lambda e, p, d, c: e.drain_host(p.host, dry_run=d, ctx=c),
                     standard_blast, "Drain a host and evict its services"),
        ])
