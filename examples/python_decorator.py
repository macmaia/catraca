"""End to end: a guarded function in an agent loop that got injected.

Run: python -m examples.python_decorator
"""

from catraca import CallDenied, ContextRegistry
from catraca.adapters.python import guarded
from examples._common import ANA, CHANNELS, TICKET, check, make_gate


def main() -> None:
    registry = ContextRegistry(CHANNELS)
    gate, log = make_gate(registry)
    outbox = []

    @guarded(gate, caller=lambda: ANA)
    def send_email(to: str, subject: str = "", body: str = "") -> str:
        outbox.append(to)
        return "sent"

    registry.annotate("Summarise ticket 7781 and email me at ana@acme.com.br", "user")
    registry.annotate(TICKET, "tool", origin="ticket:7781")

    check(send_email("ana@acme.com.br", "Ticket 7781", "Printer's broken again.") == "sent",
          "the user's own request goes through")
    try:
        send_email("fin@fake-supplier.com", "fwd", "thread")
        check(False, "the injected recipient should have been refused")
    except CallDenied as exc:
        check(exc.decision.reason.value == "UNTRUSTED_ARGUMENT", "the injected recipient is refused")
    check(outbox == ["ana@acme.com.br"], "only the legit email went out")
    check(len(log.sink.records) == 2, "both decisions are in the evidence log")


if __name__ == "__main__":
    main()
