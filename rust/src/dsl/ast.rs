use std::fmt;

/// The event types of the frozen v1 alphabet.
///
/// Each corresponds to a single kernel event that names its own argument. This is
/// the admission criterion for the alphabet, stated in `formal-semantics.md`
/// section 1.1, and it is why the enum is closed: adding a variant is a
/// specification revision, not an implementation change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EventType {
    Exec,
    Write,
    Open,
    Delete,
}

impl EventType {
    pub const ALL: [EventType; 4] =
        [EventType::Exec, EventType::Write, EventType::Open, EventType::Delete];

    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Exec => "EXEC",
            EventType::Write => "WRITE",
            EventType::Open => "OPEN",
            EventType::Delete => "DELETE",
        }
    }

    pub fn from_keyword(word: &str) -> Option<Self> {
        match word {
            "EXEC" => Some(EventType::Exec),
            "WRITE" => Some(EventType::Write),
            "OPEN" => Some(EventType::Open),
            "DELETE" => Some(EventType::Delete),
            _ => None,
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The enforcement actions a policy may specify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Deny,
    Alert,
    Allow,
}

impl Action {
    pub const ALL: [Action; 3] = [Action::Deny, Action::Alert, Action::Allow];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Deny => "DENY",
            Action::Alert => "ALERT",
            Action::Allow => "ALLOW",
        }
    }

    pub fn from_keyword(word: &str) -> Option<Self> {
        match word {
            "DENY" => Some(Action::Deny),
            "ALERT" => Some(Action::Alert),
            "ALLOW" => Some(Action::Allow),
            _ => None,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An element of the event alphabet: a pair (type, argument).
///
/// Equality is structural, as required by `formal-semantics.md` section 1.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Event {
    pub event_type: EventType,
    pub arg: String,
}

impl Event {
    pub fn new(event_type: EventType, arg: impl Into<String>) -> Self {
        Self { event_type, arg: arg.into() }
    }

    /// The surface syntax for this event, e.g. `EXEC("/bin/sh")`.
    pub fn label(&self) -> String {
        format!("{}(\"{}\")", self.event_type, self.arg)
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A policy: a name, a version, an event pattern, and an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub version: u32,
    pub sequence: Vec<Event>,
    pub action: Action,
}
