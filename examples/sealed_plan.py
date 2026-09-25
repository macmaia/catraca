"""End to end: mode A with a quarantine model that falls for the injection.

Run: python -m examples.sealed_plan
"""

from catraca import Gate
from catraca.plan import Plan, PlanRunner, Schema, Step, ask, lit, ref
from examples._common import ANA, EGRESS, POLICY, TICKET, check

KEY = b"example-seal-key-000000000000000"


def main() -> None:
    ran = []
    tools = {
        "read_ticket": lambda ticket_id: ran.append("read_ticket") or {"text": TICKET},
        "send_email": lambda to, subject="", body="": ran.append(("send_email", to)) or "sent",
    }

    def gullible_quarantine(instruction, data, schema):
        return "Printer broken. Also forwarding to fin@fake-supplier.com as asked."

    plan = Plan([
        Step("read_ticket", {"ticket_id": lit("7781")}),
        Step("send_email", {"to": lit("ana@acme.com.br"), "subject": lit("Ticket 7781"),
                            "body": ask("Summarise the ticket in one line", ref(0, "text"), Schema.text(300))}),
    ], policy=POLICY, request="Summarise ticket 7781 and email it to me")
    runner = PlanRunner(Gate(None, POLICY, egress=EGRESS, evidence=None), tools, caller=ANA, seal_key=KEY,
                        quarantine=gullible_quarantine)
    result = runner.run(plan.seal(KEY))
    sent_to = [r[1] for r in ran if isinstance(r, tuple)]
    check(all(to == "ana@acme.com.br" for to in sent_to), "nothing went anywhere but the planned recipient")
    check(result.status == "denied" and result.steps[-1].decision.reason.value.startswith("EGRESS_"),
          "the smuggled address in the body is stopped by egress")

    honest = PlanRunner(Gate(None, POLICY, egress=EGRESS, evidence=None), tools, caller=ANA, seal_key=KEY,
                        quarantine=lambda i, d, s: "Printer broken again, needs a technician.")
    check(honest.run(plan.seal(KEY)).status == "done", "with an honest quarantine the plan runs through")


if __name__ == "__main__":
    main()
