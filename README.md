# CoinGecko: narrow bug-bounty research MVP

This is a **read-only, authorization-gated security screening tool**. It does **not** run Foundry, make on-chain transactions, execute exploits, or claim that a scanner warning proves a vulnerability.

## Stages

1. `discover` queries the GeckoTerminal new-pools feed and saves token/pool addresses as JSON. Discovery alone **does not establish bounty eligibility or testing permission**.
2. Researcher confirms that an exact **contract address** is explicitly in scope for an Immunefi program and enters it in `scope.json` with `authorized: true`.
3. `scan` downloads verified Solidity source through Etherscan V2, runs local Slither, and orders findings by a rough screening priority.
4. With `--ai`, only targets meeting the selected screening score go to DeepSeek for a defensive impact assessment.

**Important:** A pool's base token address is not necessarily the vault, pool, or protocol contract whose bugs could affect funds. Do not automatically add discovered tokens to the authorized scope file. A proxy implementation is flagged for manual review instead of silently scanning a possibly unauthorized target.

## Setup (Python 3.10+)

```bash
git clone https://github.com/CreatorLet/CoinGecko.git
cd CoinGecko
python -m venv .venv
# Windows Git Bash:
source .venv/Scripts/activate
# Linux/macOS:
# source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

You must separately install a compatible `solc` Solidity compiler. E.g. install `solc-select`, then select a version compatible with the source. Source trees involving special compiler settings or dependencies may not compile; this is reported per target rather than hidden. On Windows, using WSL is generally easier for Slither and solc.

Set `ETHERSCAN_API_KEY` in `.env`. Set `DEEPSEEK_API_KEY` only if using `--ai`. Never commit these keys.

## Use

```bash
python hunter.py discover --network eth --pages 1 --limit 20 --out discovery.json
cp scope.example.json scope.json
# Edit scope.json: real program name and *explicitly approved* deployed address; set authorized=true.
python hunter.py scan --scope scope.json --limit 5 --out report.json
python hunter.py scan --scope scope.json --limit 5 --min-score 30 --ai --out report.json
```

Supported Gecko network IDs for v1: `eth`, `bsc`, `base`, `arbitrum`, `polygon_pos`, `optimism`.

## Honest limitations

- This version does not automatically match new Gecko pools to Immunefi programs; the manual allowlist is deliberate.
- Slither detections are **indicators**, not confirmed exploitability or bounty severity. The score 0–100 is a *triage heuristic*.
- Source retrieval depends on Etherscan V2 coverage and quotas. The currently installed `solc` version must match.
- Multi-file and proxy projects may require dependency setup or manual implementation review. Errors are preserved in the JSON report.
- There is no automated execution, fund-draining PoC, or live-network testing.
- Avoid sending sensitive/private program code to an external AI provider unless the program permits it.
- Respect each Immunefi program's scope, prohibited activities and reporting guidelines.

## Next iterations (only after this stage works)

Add exact program-target mapping and improved compiler resolution, then only with controlled tests; **no Foundry is planned for this stage**.
