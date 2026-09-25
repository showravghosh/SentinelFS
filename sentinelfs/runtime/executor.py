from dataclasses import dataclass

from sentinelfs.compiler.automaton import Automaton
from sentinelfs.dsl.ast_nodes import Event


@dataclass(frozen=True)
class StepResult:
    event: Event
    from_state: str
    to_state: str
    matched: bool


@dataclass(frozen=True)
class ExecutionResult:
    policy_name: str
    policy_version: int
    final_state: str
    triggered: bool  # True iff the automaton reached its final (violation) state
    decision: str  # DENY | ALERT | ALLOW -- ALLOW is a decision, not an action
    path: tuple[StepResult, ...]


def run_trace(automaton: Automaton, trace: list[Event]) -> ExecutionResult:
    state = automaton.states[0]
    path: list[StepResult] = []

    for event in trace:
        if state == automaton.final_state:
            break  # decision already reached; automaton halts

        edge = automaton.transition_from(state)
        matched = edge is not None and edge.event == event
        to_state = edge.to_state if matched else state
        path.append(StepResult(event=event, from_state=state, to_state=to_state, matched=matched))
        state = to_state

    triggered = state == automaton.final_state
    decision = automaton.action if triggered else "ALLOW"

    return ExecutionResult(
        policy_name=automaton.policy_name,
        policy_version=automaton.policy_version,
        final_state=state,
        triggered=triggered,
        decision=decision,
        path=tuple(path),
    )
