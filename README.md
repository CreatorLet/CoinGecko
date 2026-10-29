# CoinGecko smart contract screener

Minimal pipeline: **GeckoTerminal new pools -> reserve/volume filter -> Etherscan verified token source -> Slither -> optional DeepSeek**.

No Immunefi matching, Foundry, transaction execution, or automated live-contract testing. Slither output is a **screening signal**, not proof of exploitable fund loss.

## Install

Python 3.10+ and Git are required. On Windows, WSL is recommended for Solidity tooling.

```bash
git clone https://github.com/CreatorLet/CoinGecko.git
cd CoinGecko
python -m venv .venv
source .venv/Scripts/activate  # Windows Git Bash
# On Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Install `solc-select` (`pip install solc-select`). The scanner selects the compiler version reported by Etherscan or Sourcify and installs it if needed. Source retrieval prefers Etherscan V2 and falls back to Sourcify's free public verification database. Slither must be on PATH; check with `slither --version`. Put your `ETHERSCAN_API_KEY` in `.env`. Put `DEEPSEEK_API_KEY` in `.env` only for AI mode. Don't commit `.env`.

## Step 1: Discover

```bash
python hunter.py discover --network bsc --limit 20 --out result.txt
```

The uploaded `result.txt` is already a usable discovery JSON array. If running in a fresh clone, make sure your discovery file is present locally.

## Step 2: Slither only (no DeepSeek spend)

```bash
python hunter.py scan --input result.txt --min-liquidity 10000 --limit 5 --out report.json
```

The `--limit` counts selected candidate tokens, not necessarily successful completed Slither scans. Filtering is done first, with highest-liquidity pools first; a low-liquidity or unverified contract is skipped or reported as an error. The scanner operates on the discovered **base token contract**, not automatically on the project's vault or DEX pool.

## Step 3: Optional DeepSeek review

```bash
python hunter.py scan --input result.txt --min-liquidity 10000 --min-score 30 --limit 5 --ai --out report.json
```

`--min-score` is a rough severity prioritization threshold **derived from Slither alerts**. It is not actual loss severity or a guarantee of exploitability. DeepSeek only receives source excerpts if selected findings meet the threshold.

## Limitations

- Sources must be verified and compile locally. A source version/dependency mismatch may cause a Slither error.
- Proxies are flagged rather than automatically scanning implementation addresses.
- Token contracts frequently lack the money-managing logic of an associated DeFi protocol.
- GeckoTerminal's reported reserves can be volatile or manipulated, so liquidity is only a first-pass screening metric.
- The tool doesn't assert Immunefi eligibility or authorization. Use passive analysis of publicly available code only; follow each program's rules before further testing or disclosure.
- No Foundry or on-chain interactions are used.

## Colab: rerun after compiler fix

```python
%cd /content/CoinGecko
!git pull origin main
!pip install -q solc-select
!python hunter.py scan --input discovery.json --min-liquidity 10000 --limit 5 --out report.json
```

No DeepSeek credits are used without `--ai`. A previous zero severity score means the scanner did not surface scored findings, not that the contract is proved safe.


### Source-provider fallback

The scanner tries Etherscan V2 when `ETHERSCAN_API_KEY` is configured. If the explorer has no verified source or its source request fails, it tries Sourcify's public V2 contract lookup. The report records `source_provider` so you can see which source was used. Neither service can return original source for a contract that is not verified in its database.


## Source-level review signals

Slither's own score can be zero when it only reports informational/optimization findings or no findings. To keep this from being the only filter, the scanner also checks first-party source files for review cues such as `delegatecall`, `selfdestruct`, upgrade hooks, low-level calls, `tx.origin`, privileged mint functions, blacklist/transfer controls, adjustable fees, and withdraw/rescue functions.

The report separates:
- `score`: Slither-based prioritization score.
- `source_signal_score`: a simple, heuristic score for source-code patterns needing review.
- `review_score`: the sum capped at 100; with `--ai`, DeepSeek is called only when this reaches `--min-score`.
- `source_risk_signals`: which patterns were detected and source locations.

These are **triage cues, not vulnerability severity ratings**. Legitimate contracts may use these patterns, and a contract with no signals may still have a serious business-logic bug. The AI assessment should be treated as a hypothesis until independently verified. Third-party dependency files such as OpenZeppelin are excluded from source-signal scoring to reduce noise.

Example:
```bash
python hunter.py scan --input discovery.json --min-liquidity 10000 --min-score 30 --limit 5 --ai --out report.json
```
The terminal output shows Slither, source-signal, and combined review scores independently.


## Creator-linked contract discovery

Each static scan now also requests Etherscan V2 contract-creation metadata. Where the creator address and target creation transaction can be found in its indexed transaction history, the report lists up to 20 contracts created by the same address within 14 days of the target's creation transaction. It uses direct creation transactions and indexed internal CREATE/CREATE2 records.

This is only a relationship heuristic. A shared deployer and nearby deployment time do **not** prove contracts belong to the same project. The scanner records these as `creation_context.related_deployments`; it does not automatically scan these addresses or call DeepSeek on them. Review the code and source verification of each related address before adding it to a future scan.

The lookup is skipped if `ETHERSCAN_API_KEY` is unavailable, and partial if the target creation transaction is not present in the creator's recent indexed history (the current query checks up to 100 recent records per transaction endpoint). API plans and chain coverage may limit results.
