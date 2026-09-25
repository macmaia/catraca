"""catraca: provenance-aware authorisation for agent tool calls.

Labels and channels, the context registry (mode B), the gate with its
confirmation round trip, the declarative policy, egress checks, the
evidence log, and sealed plans (mode A, in ``catraca.plan``). Framework
adapters live in ``catraca.adapters``. No runtime dependencies.

See docs/architecture.md and docs/threat-model.md in the repo.
"""

from .channels import Channel, ChannelConfig
from .confirmations import ConfirmationStore, MemoryBackend, PendingBackend
from .egress import Egress, EgressRules, Target
from .evidence import EvidenceLog, JsonlFileSink, MemorySink, RotatingJsonlSink
from .errors import CallDenied, CatracaError, ConfigError, ConfirmationRequired, LabelError, RegistryError
from .gate import (
    ArgProvenance,
    Caller,
    Confirmation,
    Decision,
    DecisionRequest,
    EdgeLabel,
    Gate,
    Policy,
    PolicyResult,
    Reason,
    Verdict,
)
from .policy import ArgRule, DeclarativePolicy, LintWarning, ToolPolicy
from .labels import PUBLIC, Confidentiality, Integrity, Label
from .registry import ContextRegistry, Resolution, Rule

__version__ = "0.1.0"

__all__ = [
    "ArgProvenance",
    "ArgRule",
    "CallDenied",
    "Caller",
    "CatracaError",
    "Channel",
    "ChannelConfig",
    "Confidentiality",
    "ConfigError",
    "Confirmation",
    "ConfirmationRequired",
    "ConfirmationStore",
    "ContextRegistry",
    "Decision",
    "DecisionRequest",
    "DeclarativePolicy",
    "EdgeLabel",
    "Egress",
    "EgressRules",
    "EvidenceLog",
    "Gate",
    "Integrity",
    "JsonlFileSink",
    "Label",
    "LabelError",
    "LintWarning",
    "MemoryBackend",
    "MemorySink",
    "PUBLIC",
    "PendingBackend",
    "Policy",
    "PolicyResult",
    "Reason",
    "RegistryError",
    "Resolution",
    "RotatingJsonlSink",
    "Rule",
    "Target",
    "ToolPolicy",
    "Verdict",
]
