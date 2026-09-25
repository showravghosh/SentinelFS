from .ast_nodes import Policy
from .errors import CompileError


def validate(policy: Policy) -> None:
    if not policy.name:
        raise CompileError("Policy name must not be empty")
    if policy.version < 1:
        raise CompileError(f"Policy version must be >= 1, got {policy.version}")
    if len(policy.sequence) == 0:
        raise CompileError("Policy must contain at least one event (ON ...)")
    for event in policy.sequence:
        if not event.arg:
            raise CompileError(f"{event.type} event has an empty argument")
