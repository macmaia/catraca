"""Exceptions. A refusal is always an error you can catch, never a quietly degraded value."""


class CatracaError(Exception):
    """Base class for everything this package raises."""


class LabelError(CatracaError, ValueError):
    """Bad label, scope or serialised form."""


class ConfigError(CatracaError, ValueError):
    """Bad channel config. We never load a broken config silently."""


class RegistryError(CatracaError):
    """The context registry was used the wrong way."""


class CallDenied(CatracaError):
    """The gate said no. Carries the full decision so you can log it or show it.

    The message tells you what to do next, not just what went wrong.
    """

    def __init__(self, decision):
        self.decision = decision
        super().__init__(_denied_message(decision))


class ConfirmationRequired(CatracaError):
    """The gate wants a human to confirm the literal value before the call goes ahead.

    Don't treat this as a soft allow. Show ``decision.confirmation`` to the person,
    get an explicit yes, and only then call the tool.
    """

    def __init__(self, decision):
        self.decision = decision
        conf = decision.confirmation
        args = ", ".join(c.argument for c in conf) if conf else "?"
        super().__init__(
            f"call to {decision.tool!r} needs human confirmation of: {args}. "
            "The value came from a trusted source but also shows up in untrusted content. "
            "Show the literal value to the user and only proceed on an explicit yes, by calling "
            "the gate again with confirmation=decision.confirmation_token."
        )


_HINTS = {
    "UNKNOWN_TOOL": "declare the tool in your policy if it should be callable.",
    "UNTRUSTED_ARGUMENT": (
        "the value came from untrusted content. If the user really meant it, have them "
        "type it themselves, or relax the policy for that argument if it's harmless."
    ),
    "NO_POLICY_MATCH": "nothing in the policy allowed this call, and the default is deny.",
    "INTERNAL_ERROR": "something broke inside the gate, so it failed closed. Check the logs.",
    "INVALID_POLICY_RESULT": "the policy returned something that isn't a PolicyResult. Fix the policy.",
    "CONFIRMATION_NOT_ELIGIBLE": (
        "the policy asked for confirmation, but the case isn't a pure coincidence, so the gate denied it."
    ),
    "CALLER_NOT_ALLOWED": "this tenant or user isn't in the tool's 'callers' list.",
    "UNDECLARED_ARGUMENT": "the call has an arg the policy doesn't declare. Declare it (the defaults are strict).",
    "ARGUMENT_CONSTRAINT": "an arg value doesn't match its 'one_of' or 'pattern' rule.",
    "CONFIDENTIALITY_VIOLATION": "an arg carries data that isn't allowed to flow to this caller's scope.",
    "DESTINATION_NOT_ALLOWED": "the destination isn't in the tool's 'destinations' list.",
    "EGRESS_NOT_ALLOWED": "the call sends something to a host or address that isn't on the egress allowlist.",
    "EGRESS_BAD_SCHEME": "a destination uses a scheme the egress rules don't allow (https only by default).",
    "EGRESS_IP_LITERAL": "a destination is a raw IP address, which the egress rules don't allow by default.",
    "EGRESS_PRIVATE_NETWORK": "a destination points at localhost or a private network.",
    "EGRESS_UNTRUSTED": "a destination came from untrusted content, even if its host is allowed.",
    "EVIDENCE_UNAVAILABLE": "the decision couldn't be written to the evidence log, so the call was denied.",
    "CONFIRMATION_INVALID": "the confirmation token is unknown, expired or already used. Ask the user again.",
    "CONFIRMATION_MISMATCH": (
        "the call doesn't match what the user confirmed (tool, caller, destination or values changed). "
        "The token's been burnt, so ask again with the new values."
    ),
}


def _denied_message(decision) -> str:
    hint = _HINTS.get(decision.reason.value, "check the decision record for details.")
    return f"call to {decision.tool!r} denied ({decision.reason.value}): {hint}"
