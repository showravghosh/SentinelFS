from dataclasses import dataclass

from sentinelfs.dsl.ast_nodes import Event, Policy
from sentinelfs.dsl.validator import validate


@dataclass(frozen=True)
class Transition:
    from_state: str
    to_state: str
    event: Event


@dataclass(frozen=True)
class Automaton:
    policy_name: str
    policy_version: int
    states: tuple[str, ...]
    transitions: tuple[Transition, ...]
    final_state: str
    action: str  # DENY | ALERT

    def transition_from(self, state: str) -> Transition | None:
        for t in self.transitions:
            if t.from_state == state:
                return t
        return None


def compile_policy(policy: Policy) -> Automaton:
    """Compiles a validated Policy AST into a deterministic finite automaton.

    State q_i has exactly one outgoing edge, on policy.sequence[i]; every
    other event is a self-loop (q_i -> q_i). This encodes the DSL's
    violation semantics: the required events must occur in order, with
    arbitrary other events interleaved.
    """
    validate(policy)

    states = tuple(f"q{i}" for i in range(len(policy.sequence) + 1))
    transitions = tuple(
        Transition(from_state=f"q{i}", to_state=f"q{i + 1}", event=event)
        for i, event in enumerate(policy.sequence)
    )

    return Automaton(
        policy_name=policy.name,
        policy_version=policy.version,
        states=states,
        transitions=transitions,
        final_state=states[-1],
        action=policy.action,
    )
