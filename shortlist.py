"""Offline triage of Frontier/Hunter reports. Requires no RPC, key, or network calls.

Does not estimate TVL for arbitrary contracts, establish bounty scope, or claim
a vulnerability. Treat scores as prioritization signals only.
"""
import argparse
import json
from pathlib import Path

TUTORIAL_TERMS = ("tutorial", "challenge", "scaffold", "course", "homework", "lesson", "workshop")
UNDEPLOYED_TERMS = ("not deployed", "not yet deployed", "nothing has been broadcast",
                    "prepared but unexecuted", "deployment in progress")
LOW_VALUE_FINDINGS = {"shadowing-local", "naming-convention", "dead-code", "solc-version"}


def load_records(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array, not a notebook transcript")
    return [item for item in data if isinstance(item, dict)]


def assess(row, kind):
    reasons = []
    score = 0
    if kind == "github":
        name = str(row.get("full_name") or "")
        desc = str(row.get("description") or "")
        combined = (name + " " + desc).lower()
        surfaces = set(row.get("fund_handling_surface_types") or [])
        source_score = min(100, max(0, int(row.get("source_signal_score") or 0)))
        score = min(35, source_score) + min(30, 7 * len(surfaces))
        if row.get("asset_bearing_code_candidate"):
            score += 12
            reasons.append("Contains fund-handling code; does not prove assets are deposited")
        if "financial-entrypoint" in surfaces and ("token-transfer" in surfaces or "native-value-transfer" in surfaces):
            score += 10
            reasons.append("Financial entrypoints and value movement occur in the source")
        if row.get("duplicate_repository_of"):
            score -= 45
            reasons.append("Duplicate source: lower novelty")
        if any(word in combined for word in TUTORIAL_TERMS):
            score -= 35
            reasons.append("Likely educational or scaffolded project")
        if any(word in combined for word in UNDEPLOYED_TERMS):
            score -= 30
            reasons.append("Description indicates deployment has not occurred")
        reasons.append("GitHub code alone does not establish deployment, liquidity, or bounty scope")
        identity = name
        category = "source_only"
        address = None
    else:
        identity = str(row.get("address") or "")
        address = identity
        category = "verified_onchain" if kind == "verified" else "screened_onchain"
        score = 15 if kind == "verified" else 10
        if kind == "verified":
            reasons.append("Recently source-verified on chain; source still needs inspection")
        else:
            findings = row.get("findings") or []
            impacts = [str(f.get("impact") or "").lower() for f in findings if isinstance(f, dict)
                       and f.get("check") not in LOW_VALUE_FINDINGS]
            score += min(45, 22 * impacts.count("high") + 8 * impacts.count("medium"))
            score += min(25, int(row.get("source_signal_score") or 0))
            if row.get("status") != "screened" and row.get("status") != "reviewed":
                score -= 30
                reasons.append("Source scan not completed")
            liquidity = float(row.get("reserve_usd") or 0)
            if liquidity > 0:
                score += 8
                reasons.append("Liquidity is associated with a pool, not verified contract assets at risk")
            if not impacts and not row.get("source_risk_signals"):
                reasons.append("No substantive static-analysis finding in the completed scan")
        reasons.append("No evidence yet of an exploitable unprivileged path or bounty eligibility")
    return {"candidate": identity, "address": address, "category": category,
            "priority_score": max(0, min(100, score)),
            "reasons": reasons, "confirmed_vulnerability": False,
            "bounty_scope_confirmed": False}


def main():
    parser = argparse.ArgumentParser(description="Rank existing scan outputs offline (no API, no RPC)")
    parser.add_argument("--github", default=None, help="github-report.json")
    parser.add_argument("--verified", default=None, help="frontier-verified-bsc.json")
    parser.add_argument("--screened", default=None, help="bsc-scan-report.json")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--out", default="shortlist.json")
    args = parser.parse_args()
    if args.limit < 1 or not any((args.github, args.verified, args.screened)):
        parser.error("Supply at least one input and a positive --limit")
    rows = []
    for kind, path in (("github", args.github), ("verified", args.verified), ("screened", args.screened)):
        if path:
            rows.extend(assess(row, kind) for row in load_records(path))
    # Prefer completed onchain analyses over uninspected verification entries
    # with equal score; never duplicate a given onchain address.
    category_rank = {"screened_onchain": 2, "source_only": 1, "verified_onchain": 0}
    rows.sort(key=lambda r: (r["priority_score"], category_rank[r["category"]]), reverse=True)
    seen, result = set(), []
    for row in rows:
        key = (row["category"] == "source_only", row["candidate"].lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
        if len(result) >= args.limit:
            break
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(result)} prioritized research leads to {args.out}")
    for row in result[:10]:
        print(f'{row["priority_score"]:>3}  {row["category"]:>18}  {row["candidate"]}')


if __name__ == "__main__":
    main()
