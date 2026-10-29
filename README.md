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
