"""MCX-2 versus MCX-3: the veto a required agent domain adds, and its liveness cost.

    python -m mcx_experiment.profiles

Reads the built-in mcx2-vs-mcx3 scenario. The agent representative's ballot
is a scripted input: the run shows what the counting rule does with an
objection, an absence, an ineligible representative, and a captured one. It
does not show that a representative would object to the right proposals,
which is the detection value Section 15.2 asks about.
"""

from __future__ import annotations

from fractions import Fraction

from mcx_experiment.protocol import DecisionType, Snapshot, Voter
from mcx_experiment.scenario import approving_subsets, run

AVAILABILITY = (Fraction(99, 100), Fraction(95, 100), Fraction(9, 10), Fraction(8, 10))


def _electorate(per_domain: int, domains: tuple[str, ...]) -> tuple[Voter, ...]:
    return tuple(Voter(f"{d}-{i}", d) for d in domains for i in range(1, per_domain + 1))


PROFILES = (
    # (label, domains in the electorate, required domains)
    ("MCX-2", ("human", "custody"), ("human", "custody")),
    ("MCX-2 + agent voters, not required", ("human", "custody", "agent"), ("human", "custody")),
    ("MCX-3", ("human", "custody", "agent"), ("human", "custody", "agent")),
)


def liveness_table(per_domain_sizes=(1, 2, 3), availability=AVAILABILITY, threshold="2/3") -> list[dict]:
    """Exact P(approve) when every voter independently shows up with probability p and approves.

    The middle profile has the MCX-3 electorate and the MCX-2 requirement, so
    comparing it with MCX-3 isolates the cost of requiring the agent domain
    from the effect of a larger denominator.
    """
    rows = []
    for size in per_domain_sizes:
        for profile, domains, required in PROFILES:
            snap = Snapshot("liveness", DecisionType.D2, {}, _electorate(size, domains), required, threshold)
            counts = approving_subsets(snap) or {}
            n = len(snap.eligible)
            rows.append(
                {
                    "profile": profile,
                    "voters_per_domain": size,
                    "electorate": n,
                    "p_approve": {
                        str(p): sum((c * p**k * (1 - p) ** (n - k) for k, c in counts.items()), Fraction(0))
                        for p in availability
                    },
                }
            )
    return rows


def veto_rows() -> list[tuple[str, str, str]]:
    report = run("mcx2-vs-mcx3")
    if report["failures"]:
        raise SystemExit("mcx2-vs-mcx3 expectations failed: " + "; ".join(report["failures"]))
    by_case: dict[str, dict[str, str]] = {}
    for c in report["conditions"]:
        case, profile = c.name.split("/")
        by_case.setdefault(case, {})[profile] = "approve" if c.verdict.approved else f"deny ({c.verdict.reason})"
    return [(case, cells.get("MCX-2", "-"), cells.get("MCX-3", "-")) for case, cells in by_case.items()]


def main() -> None:
    rows = veto_rows()
    width = max(len(r[0]) for r in rows)
    middle = max(len(r[1]) for r in rows)
    print("Same proposal; human and custody approve unless stated (scenario mcx2-vs-mcx3).\n")
    print(f"{'case'.ljust(width)}  {'MCX-2'.ljust(middle)}  MCX-3")
    for case, two, three in rows:
        print(f"{case.ljust(width)}  {two.ljust(middle)}  {three}")
    print("\nExact P(approve), each voter present independently with probability p, threshold 2/3:\n")
    table = liveness_table()
    ps = list(table[0]["p_approve"])
    label = max(len(row["profile"]) for row in table)
    print(f"{'profile'.ljust(label)}  per domain  electorate  " + "  ".join(f"p={p:<6}" for p in ps))
    for row in table:
        cells = "  ".join(f"{float(row['p_approve'][p]):<8.4f}" for p in ps)
        print(f"{row['profile'].ljust(label)}  {row['voters_per_domain']:<10}  {row['electorate']:<10}  {cells}")
    print(
        "\nShown: a required agent domain can block a proposal the other two domains approve, and an absent"
        "\nor ineligible representative blocks it too. On the same electorate, requiring the agent domain"
        "\nnever raises P(approve); in this table it costs most with one voter per domain (p^3 against p^2)."
        "\nAgainst MCX-2's smaller electorate the comparison is mixed: more voters make a 2/3 bar easier to"
        "\nclear when p > 2/3. The model assumes independent availability and that everyone present approves."
        "\nNot shown: that the representative objects to harmful proposals and not to benign ones. A captured"
        "\nrepresentative approves and adds nothing. Detection value needs a representative and a workload to"
        "\nmeasure, which this harness does not have."
    )


if __name__ == "__main__":
    main()
