# CoinGecko smart contract screener


## Autonomous Hunter (recommended)

This uses only the credentials already configured in your environment: `ETHERSCAN_API_KEY`, `GOPLUS_API_KEY`, `GOPLUS_API_SECRET`, `NODEREAL_API_KEY`, and `DEEPSEEK_API_KEY`. It does **not** require `BSC_RPC_URL` or another API key. The optional GitHub discovery commands use `GITHUB_TOKEN`.

```bash
python hunter.py autopilot --network bsc --pages 3 --limit 50 --verified-limit 100 --max-screened 40 --max-ai-reviews 6 --out hunter-autopilot.json
```

Hunter discovers new GeckoTerminal pools and newly verified Sourcify contracts, then runs source retrieval, NodeReal/Etherscan/GoPlus context, Slither and first-party source checks. It estimates the candidate's observable value and checks public/external entry points before DeepSeek is shown a compact brief. **DeepSeek only receives a candidate when both conditions pass:**
- There is a plausible unprivileged/public entry point into asset-moving or external-call logic; and
- The observable value is at least **$500**, or an unprivileged intermediary/callback/forwarder path merits the specific low-value exception.

Admin/owner/governance-only powers do not qualify on their own. Unusual function names are not required: Hunter follows internal helper calls and recognises typed interface calls as well as raw `.call` patterns. DeepSeek decides whether a surfaced path is genuinely attacker-controlled or merely calls a fixed trusted component.

The exposure estimate uses the maximum of associated token/pool liquidity and directly observed contract-held balances; it does **not** add them together. Pool liquidity is an economic-size proxy, not proof that the contract owns or controls those funds. The report shows whether direct balances were checked and whether the valuation lookups were complete. An unavailable balance/price lookup is not treated as proof of an empty contract.

For a candidate below $500, a public function reaching a low-level or nonstandard external call is only a *possible* intermediary. DeepSeek must inspect whether an ordinary caller can influence the destination, payload, callback, or transaction being processed. Calls to fixed trusted tokens/oracles/protocols do not automatically deserve a full review.

DeepSeek operates Hunter through five allowlisted commands: discover, screen the next candidate, deep-review the current candidate, skip it, and finish. It cannot run arbitrary shell commands. Each review is saved to the report; a separate checkpoint tracks processed addresses and review usage. If the process stops while a candidate awaits a decision, the next run re-screens that address.

### Run continuously on a server

```bash
python hunter.py autopilot --network bsc --continuous --interval-seconds 900 --max-hours 0 --max-ai-reviews 6 --out hunter-autopilot.json
```

This checks for fresh candidates every 15 minutes and stops after six full DeepSeek reviews in total. Increase `--max-ai-reviews` to allow more reviews; set it to `0` for unlimited reviews (uncapped token spend). Set `--max-hours 24` for a one-day service window. Run it under `systemd`, Supervisor, Docker restart policy, or another process manager on a machine with persistent storage. Keep the report and checkpoint files on that storage; do not put your `.env` in GitHub.

Use `python hunter.py autopilot --help` to see all limits. The normal one-cycle run is safer for your first run.

No transaction execution, exploit execution, or live-contract testing is performed. Slither and source heuristics are screening evidence, not proof of an exploitable vulnerability.

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

The `--limit` counts selected candidate tokens, not necessarily successful completed Slither scans. Filtering is done first, with highest-liquidity pools first; a low-liquidity or unverified contract is skipped or reported as an error. The scanner operates on the discovered **base token contract**, not automatically on the project's vault or DEX pool. The autopilot combines these pool-token entries with recently verified contracts and performs the same value/access checks before DeepSeek.


## Frontier discovery: freshness-first sources

The old DeFiLlama TVL-ranked discovery command has been removed. Use independent source and deployment signals instead:

1. **Newly verified contracts:** `python frontier.py verified --network bsc --limit 100 --out verified-discovery.json`
2. **New or recently changed source repositories:** `python frontier.py github --days 7 --limit 30 --out github-discovery.json`
3. **Static triage for GitHub source:** `python frontier.py scan-github --input github-discovery.json --limit 15 --out github-report.json`
4. **Current bounty and audit leads:** `python frontier.py audits --out audit-pipelines.json`
5. **Recently mined direct deployments:** `python frontier.py deployments --network bsc --blocks 20 --limit 100 --out deployment-discovery.json`
6. **Provider-visible pending creations:** `python frontier.py mempool --network bsc --seconds 60 --limit 1000 --out pending-creations.json`

The existing GeckoTerminal `discover` workflow remains available for new DEX pools. For deployment commands, configure a read-only HTTP or WebSocket RPC URL in your local runtime. Never commit RPC credentials.

GitHub source search records repository creation and push times. The scanner skips test/fixture/deployment-script and known vendored-library paths, hashes source files to flag identical code copied into different repositories, and avoids repeating DeepSeek reviews for exact duplicate repositories. The GitHub report separately records asset-handling surface markers (token transfers, financial entry points, balance/liability accounting, and protocol calls); these are for manual-review prioritization only and do not raise the vulnerability score by themselves. Static pattern matches remain triage hints, not vulnerability findings.

When you want DeepSeek to inspect asset-bearing logic that has few syntax-based warnings (for example, a paywall or accounting-heavy vault), opt in explicitly and keep the limit small:

~~~bash
python frontier.py scan-github --input github-discovery.json --limit 5 --min-score 20 --ai --ai-fund-handling --out github-report-ai.json
~~~

This flag requires `DEEPSEEK_API_KEY` and can consume credits. It expands AI review to candidates whose source shows both a financial entry point and asset-flow surface, even if the heuristic warning score is low. It does **not** label those candidates vulnerable.

The audit output keeps current/upcoming opportunities separate from unverified project directories and ended contests. Immunefi records include recent smart-contract scope additions where the public feed exposes them. Confirm scope, timing, eligibility and rules on the official platform before conducting research.

These feeds are incomplete by design: Sourcify verification time is not necessarily deployment time; block scans miss internal factory CREATE/CREATE2 events; and a WebSocket provider does not expose a global mempool. The scanner performs passive source analysis and read-only data collection only. It sends no transactions and performs no live exploit testing.

## Step 3: Optional gated DeepSeek review

```bash
python hunter.py scan --input discovery.json --min-exposure-usd 500 --limit 5 --ai --out report.json
```

The same hard gate applies to both manual and autonomous runs: DeepSeek only runs when the scanner detects a plausible unprivileged public/external path and either $500 or more of observable value or a credible unprivileged intermediary/callback exception. `--min-score` remains a report-ranking hint; it is no longer the AI access-control gate.

## Limitations

- Sources need to be verified and compile locally. If neither Etherscan nor Sourcify supplies source, the target is marked `skipped_low_transparency`; it is not treated as safe.
- One verified proxy implementation is followed and analyzed at the proxy address; nested or unresolved proxies are marked `skipped_low_transparency` rather than guessed at.
- Token contracts frequently lack the money-managing logic of an associated DeFi protocol.
- GeckoTerminal's reported reserves can be volatile or manipulated, so liquidity is only a first-pass screening metric.
- The tool doesn't assert Immunefi eligibility or authorization. Use passive analysis of publicly available code only; follow each program's rules before further testing or disclosure.
- Etherscan/GeckoTerminal lookups are read-only; no transactions are sent and no live exploit tests are run.

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
- follows one verified proxy implementation; nested/unresolved proxy implementations are skipped rather than guessed at;
- records GoPlus hidden-owner / non-open-source flags as transparency caveats;
- records GoPlus flags as context but does not treat token-owner controls as unprivileged vulnerabilities;
- estimates economic exposure using pool/token liquidity and, when needed, read-only direct balance checks;
- requires a public/unprivileged code path plus the $500 value floor or a possible intermediary exception before a candidate reaches DeepSeek; DeepSeek then decides whether a below-threshold external call is genuinely interceptable.

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


## Bounded factory-candidate review

After resolving creation metadata, the scanner performs **one extra static review at most**: it inspects a `factory_candidate` only when the creator also made at least one nearby call to that same destination within the bounded history response. The result is stored in `related_contract_reviews`. It does not recursively follow candidate contracts. If verified source is missing or the candidate is an unsupported proxy, it records a low-transparency skip and continues. With `--ai`, a linked contract must pass the same unprivileged-surface and $500/intermediary gate as the main target. GoPlus risk flags alone do not trigger AI review.

This helps inspect likely factory/launchpad code without aggressively chasing every related address. A candidate factory is not necessarily a fund-holding protocol; review its role and source before spending further time on it.


## No-new-API / no-RPC shortlist (Colab)

You **do not need** to configure `BSC_RPC_URL` or add another API key to run this path. The public Sourcify verified-contract feed and existing GitHub/GeckoTerminal discovery steps work without new keys. Skip `frontier.py deployments` (and `mempool`), as those commands require RPC access.

```bash
python frontier.py github --days 7 --limit 20 --per-query 10 --out github-discovery.json
python frontier.py scan-github --input github-discovery.json --limit 10 --out github-report.json
python frontier.py verified --network bsc --limit 100 --out frontier-verified-bsc.json
python hunter.py scan --input frontier-verified-bsc.json --min-liquidity 0 --limit 12 --min-score 30 --out verified-screened-bsc.json
python shortlist.py --github github-report.json --verified frontier-verified-bsc.json --screened verified-screened-bsc.json --limit 30 --out shortlist.json
```

`hunter.py scan` recognizes `target_kind=verified_contract` and does **not** require pool liquidity for those entries. It uses the existing verified-source providers and local Slither. Keep `--ai` off until a candidate is manually worth pursuing. `shortlist.py` uses **local report files only**, makes no requests and sends no content to DeepSeek. Its priority score is merely a research queue, **not** verified fund exposure, exploitability, deployment confirmation for GitHub-only source, or bounty eligibility.

If using Colab, run `!git pull origin main` and prefix each command with `!`. Save each produced JSON file individually; pasting notebook transcript plus arrays into `report.json` is not machine-readable JSON.
