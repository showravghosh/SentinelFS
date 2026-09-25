from dataclasses import dataclass


@dataclass(frozen=True)
class Event:
    type: str  # one of EVENT_TYPES
    arg: str

    def label(self) -> str:
        return f'{self.type}("{self.arg}")'


@dataclass(frozen=True)
class Policy:
    name: str
    version: int
    sequence: tuple[Event, ...]
    action: str  # DENY | ALERT | ALLOW
