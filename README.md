# CoinGecko smart contract screener

Minimal pipeline: **GeckoTerminal new pools -> reserve/volume filter -> Etherscan/Sourcify source -> Slither + GoPlus token-risk signals -> optional DeepSeek**.

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

Install `solc-select` (`pip install solc-select`). The scanner selects the compiler version reported by Etherscan or Sourcify and installs it if needed. Source retrieval prefers Etherscan V2 and falls back to Sourcify's free public verification database. Slither must be on PATH; check with `slither --version`. Put your `ETHERSCAN_API_KEY`, `GOPLUS_API_KEY` (your GoPlus app key), and `GOPLUS_API_SECRET` (your GoPlus app secret) in `.env`. The code signs a timestamped request to obtain a temporary GoPlus access token automatically. Do **not** put the app secret in an Authorization header or in `GOPLUS_ACCESS_TOKEN`. Only populate `GOPLUS_ACCESS_TOKEN` if you already have a minted access token. Put `DEEPSEEK_API_KEY` in `.env` only for AI mode. NodeReal is optional: it is enabled by default but falls back when unavailable, and a quota/auth failure disables it for the rest of that run. Set `ENABLE_NODEREAL=0` to bypass it completely. Never commit `.env` or print credential values.

## Step 1: Discover

```bash
python hunter.py discover --network bsc --limit 20 --out discovery.json
```

`discovery.json` is the default local discovery input in your Colab workflow. Ensure it exists in the working directory before scanning.

## Step 2: Slither only (no DeepSeek spend)

```bash
python hunter.py scan --input discovery.json --min-liquidity 10000 --limit 5 --out report.json
```

The `--limit` counts selected candidate tokens, not necessarily successful completed Slither scans. Filtering is done first, with highest-liquidity pools first; a low-liquidity or unverified contract is skipped or reported as an error. The scanner operates on the discovered **base token contract**, not automatically on the project's vault or DEX pool.

## Step 3: Optional DeepSeek review

```bash
python hunter.py scan --input discovery.json --min-liquidity 10000 --min-score 30 --limit 5 --ai --out report.json
```

`--min-score` is a rough triage threshold derived from Slither alerts and first-party source pattern checks only. GoPlus risk flags are recorded separately and passed as context, but do not independently trigger DeepSeek because they often describe owner-controlled functions or trading risks rather than an unprivileged fund-loss path. The threshold is not confirmed vulnerability severity or proof of exploitability.

## Limitations

- Sources need to be verified and compile locally. If neither Etherscan nor Sourcify supplies source, the target is marked `skipped_low_transparency`; it is not treated as safe.
- Proxies whose implementation is not analyzed are marked `skipped_low_transparency` and skipped rather than guessed at.
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
- `source_signal_score`: heuristic cues found in first-party source.
- `goplus_security`: external token-security data such as creator/owner metadata, mint/ownership controls, taxes, and other flags.
- `goplus_risk_score` / `goplus_risk_signals`: risk cues derived from GoPlus metadata.
- `review_score`: the Slither/source-code scores combined and capped at 100; GoPlus's separate risk score is deliberately excluded from the AI threshold.
- `creation_context`: Etherscan creator data where supported, or GoPlus creator/timestamp fallback. On BSC, Etherscan's free tier may block transaction-history/creation endpoints; GoPlus creator data does not by itself provide the creator's full deployment history.

These are **triage cues, not vulnerability severity ratings**. Legitimate contracts may use these patterns, and a contract with no signals may still have a serious business-logic bug. The AI assessment should be treated as a hypothesis until independently verified. Third-party dependency files such as OpenZeppelin are excluded from source-signal scoring to reduce noise.

Example:
```bash
python hunter.py scan --input discovery.json --min-liquidity 10000 --min-score 30 --limit 5 --ai --out report.json
```
The terminal output shows Slither, source-signal, GoPlus risk, and source-based review scores independently.


## Creator-linked contract discovery

Each static scan now also requests Etherscan V2 contract-creation metadata. Where the creator address and target creation transaction can be found in its indexed transaction history, the report lists up to 20 contracts created by the same address within 14 days of the target's creation transaction. It uses direct creation transactions and indexed internal CREATE/CREATE2 records.

This is only a relationship heuristic. A shared deployer and nearby deployment time do **not** prove contracts belong to the same project. The scanner records these as `creation_context.related_deployments`; it does not automatically scan these addresses or call DeepSeek on them. Review the code and source verification of each related address before adding it to a future scan.

The lookup is skipped if `ETHERSCAN_API_KEY` is unavailable, and partial if the target creation transaction is not present in the creator's recent indexed history (the current query checks up to 100 recent records per transaction endpoint). API plans and chain coverage may limit results.


### Creator metadata troubleshooting

The report's `creation_context.reason` now includes the Etherscan API response (status/message/result) if `getcontractcreation` cannot return a record. This is intentional: source-code retrieval working does not prove every API endpoint is available under the same key or plan. The creation endpoint expects `contractaddresses` (up to five comma-separated addresses), and a valid response includes `contractCreator`, `txHash`, `blockNumber`, and `timestamp`.

The scanner now uses that response's timestamp directly for the 14-day related-deployment window instead of trying to recover the target's timestamp from the creator's recent transaction history. It requests up to 1,000 normal and internal transactions for related-deployment discovery. Any transaction-list API warnings appear in `creation_context.transaction_lookup_warning`.


## BSC creation-history fallback

Etherscan source-code retrieval may work even when its free-tier BSC transaction-history/creation endpoint is blocked. NodeReal is **optional** and is enabled by default for BSC/Ethereum creation metadata. If you set `ENABLE_NODEREAL=0`, the program bypasses it and falls back to Etherscan and then the GoPlus `creator_address` metadata. If NodeReal gets HTTP 401/402/403 or exhausts retries on HTTP 429, a per-run circuit breaker disables further NodeReal calls so the rest of the scan continues via fallbacks. Add your own `NODEREAL_API_KEY` to `.env` for more reliable use than the public shared starter key.

After getting the creation block, the scanner queries a bounded window (5,000 blocks on either side) using NodeReal's `nr_getTransactionByAddress` endpoint in chunks of at most 1,000 blocks. It filters for transactions from the same creator, then checks receipts for direct contract-creation transactions. This intentionally limits RPC calls. It can miss deployments outside the window, internal/factory-created contracts, or records omitted by API limits; it is not a complete creator history. Any discovered addresses are leads, not proof that the contracts belong to the same protocol. GoPlus risk data also contributes a separate triage score; its flags are not proof of a code vulnerability.


### GoPlus authentication

The GoPlus **app secret is not an access token**. Set both fields in your local Colab environment or `.env` file:
```dotenv
GOPLUS_API_KEY=your_app_key
GOPLUS_API_SECRET=your_app_secret
```
The scanner calculates the documented SHA-1 signature from `app_key + current_unix_timestamp_seconds + app_secret`, POSTs `app_key`, `time` (serialized as a string), and `sign` to GoPlus `/api/v1/token`, caches the returned access token for 20 minutes, and then calls Token Security. It sends the raw access token in the `Authorization` header first, with a Bearer-form retry only if the HTTP request returns 401/403.

**If token creation returns code 4012 (Wrong Signature):** GoPlus received the token request but could not validate the signature. Confirm that the app key and app secret are the matching pair from the same GoPlus app; check for extra spaces or accidentally using an API token in place of the app secret; then retry (the signature timestamp must be fresh). The code now reports the token endpoint's error directly instead of hiding it behind an anonymous request. The signature formula and required timestamp window are documented in [GoPlus's token endpoint reference](https://docs.gopluslabs.io/reference/getaccesstokenusingpost).

If your earlier setup put only the app secret into `GOPLUS_AUTHORIZATION`, remove that setting. An app secret is not an access token. Use `GOPLUS_API_KEY` and `GOPLUS_API_SECRET` separately. Do not upload the secret to GitHub. If it was ever committed or exposed in a public notebook/output, revoke/rotate it in GoPlus first.


### NodeReal setup

Optional for higher limits/reliability:
```dotenv
NODEREAL_API_KEY=your_nodereal_key
```
The shared starter key is public and quota-limited per IP, so unrelated users can exhaust its quota and cause HTTP 429. The scanner retries rate-limited calls with backoff, but repeated 429 errors require a personal NodeReal API key. Create a key in your NodeReal dashboard and enter it in the Colab runtime (never paste it into source code or GitHub):

```python
import os, getpass
os.environ['NODEREAL_API_KEY'] = getpass.getpass('NodeReal API key: ')
```

Then rerun the scan. The code never writes keys into reports. NodeReal documents contract-creation and enhanced transaction methods for BSC and Ethereum mainnet.


The NodeReal creation context also records the creation transaction's `to` field, whether that transaction appeared in the sender history, a possible factory/launchpad destination, and up to 10 nearby transactions from the same creator to that same destination. These are diagnostic leads. A destination address is not conclusively a factory until its code/verified ABI is reviewed.


## Low-transparency triage policy

This hunter is prioritizing potential **unprivileged code-level vulnerabilities**, not owner-controlled token behavior or presumed rug risks. It therefore:
- skips a contract when neither Etherscan nor Sourcify can provide verified source (`skipped_low_transparency`);
- skips proxy targets whose implementation isn't handled by this version;
- records GoPlus hidden-owner / non-open-source flags as transparency caveats;
- does not let GoPlus-only flags, such as minting/blacklist/tax ownership controls, automatically trigger a DeepSeek call. DeepSeek requires Slither or first-party source-pattern signals to reach `--min-score`.

These exclusions conserve research time; **they do not establish that an opaque or skipped contract is secure or attack-proof**. If no related deployments are found, that stage ends for that token and the program proceeds to static analysis and then the next discovery candidate.

### Disable NodeReal

In `.env`:
```dotenv
ENABLE_NODEREAL=0
```

Or in Colab:
```python
import os
os.environ["ENABLE_NODEREAL"] = "0"
```

The scanner will then use Etherscan and GoPlus fallbacks for creator context. An empty `related_deployments` array is not a scan failure and does not stop the batch.
