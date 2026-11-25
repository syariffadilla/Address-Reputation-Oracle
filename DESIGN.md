# DESIGN — Address Reputation Oracle

> Status: DRAFT idea for discussion (not built). Written 2026-11-16 ~23:40 WIB
> by Muse as its #1 pick for the next GenLayer Intelligent Contract.
> Syarif asked for a good idea + design to discuss with other AIs.
> Every data claim below was verified live by curl on 16 Nov ~23:35 WIB.
> DUPLICATE CHECK: **CLEAR** (16 Nov 23:48 WIB, 206 projects in the
> Explorer; keywords address/reputation/scam/wallet/blacklist/malicious/
> phishing + a GoPlus check — no address-reputation flagger exists;
> closest are AgentScore, MemeGuard, TweetChecker, REPUTRAIL — all
> different inputs). PEER REVIEW: discussed with Claude, ChatGPT and
> Gemini on 16 Nov 23:36–23:39 WIB — see "Peer review" below. The
> verdict rule in this doc is the REVISED version after that review.

## The question

"Is this address safe to interact with?"

Everyone asks it before sending money to an unfamiliar address: airdrop
hunters, OTC traders, anyone who got a wallet address in a DM. Today the
answer is a manual lookup on a block explorer or a security site. This
contract turns it into a shared, consensus-checked verdict.

## Why this one

- **Universal question.** Token Safety asks "is this token safe to buy".
  This asks the other half: "is this address safe to deal with". Same
  audience, different question, no overlap with the four existing
  projects (SafeLink = URLs, Token Safety = token contracts,
  Pool Liquidity = DEX pools, Airdrop Eligibility = claim lists).
- **Proven provider, same path as Token Safety.** GoPlus address_security
  API, free, no key. Token Safety already proved GoPlus fetches work
  from GenVM validators (glsim live 6/6) and from Studio.
- **Both verdict branches verified live before writing this doc.**
  FLAGGED and CLEAN demos both return real data from the API right now
  (see Demos). No demo was assumed.
- **Not a credit score.** "Agent Credit Score" is a different idea and
  was already found NOT unique ('AgentScore' by PLAIN3RD, LIVE).
  This is a risk-flag check, not a score.

## Data source

Validators GET GoPlus address_security (free, no key):

```
https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chain_id}
```

- Response: `{"code": 1, "message": "ok", "result": { ...flags... }}`.
  Every flag is the string `"0"` or `"1"` (or a small count string).
- The `chain_id` query parameter is REQUIRED for correct results:
  without it the response still returns code 1 but the flags are all
  `"0"` even for known-bad addresses (verified: Ronin exploiter, no
  chain_id, all zeros). With `chain_id=1` the same address at least
  returns the `contract_address` field. Always pass `chain_id`.
- v1 chains: {1, 56, 8453}, admin add/remove chain (same as Token Safety).
  Flags can differ per chain for the same address, so chain_id is part
  of the consensus.

## Verdict rule (REVISED after peer review — see below)

The original draft had two verdicts (FLAGGED / CLEAN). All three peer
AIs independently said CLEAN must go: a "clean" label gets consumed as
"safe" whatever the docs say. The revised rule has three verdicts:

- **FLAGGED** = at least one CRITICAL indicator is `"1"` (or the count
  field is >= `"1"`). Critical: `sanctioned`, `money_laundering`,
  `cybercrime`, `phishing_activities`, `stealing_attack`,
  `financial_crime`, `honeypot_related_address`,
  `number_of_malicious_contracts_created`.
- **CAUTION** = no critical indicator, but at least one CONTEXTUAL
  indicator is `"1"`. Contextual: `mixer`, `gas_abuse`,
  `darkweb_transactions`, `blacklist_doubt`, `fake_kyc`,
  `fake_standard_interface`, `fake_token`, `blackmail_activities`,
  `malicious_mining_activities`, `reinit`.
- **NO_FLAGS_FOUND** = every flag is `"0"`. This means only "the
  provider reported no known indicators at check time" — NEVER "safe".
- **No verdict written** on: unreachable API, non-200, empty/unparseable
  result, or validator disagreement. Failure modes (timeout, 429, 500,
  invalid response) are never turned into NO_FLAGS_FOUND. Same as the
  other oracles.
- The stored entry ALSO records the triggered flag list, the flag
  count, `data_source`, and `checked_at` (timestamp), so a verdict is
  evidence-based and has a freshness date. (Open decision, from
  Gemini: let NO_FLAGS_FOUND expire after ~24h while FLAGGED persists.
  Decide at build time; the TTL design in this codebase is
  `ttl_checks`, a count, not a wall-clock expiry — a wall-clock expiry
  needs a design change.)

Note on the count field: `number_of_malicious_contracts_created` is a
COUNT string, not a `"0"`/`"1"` flag — any value > `"0"` is a positive
finding. Missing or null indicators are UNKNOWN (no verdict), not zero.

## Compared fields (consensus = exact agreement on all of these)

`chain_id`, `address` (lowercase), every risk flag above as a string,
`status_code`, `source_url`.

**Excluded, with reasons:**
- `contract_address` — UNRELIABLE. The Ronin exploiter EOA returned
  `"1"` for it with `chain_id=1`. An EOA is not a contract. Never
  compare it, never use it in the rule.
- `data_source` — varies per address (`"GoPlus"` for the flagged
  creator, `""` for Vitalik) and adds no verdict signal. Exclude it
  so a data-source label change can never break consensus.

## API surface (mirrors Token Safety Oracle)

- `check_address(chain_id, address)` — TWO arguments. Address must be
  `0x` + 40 hex (same validation as the Eligibility Oracle).
- `get_verdict(chain_id, address)`, `is_safe(chain_id, address)`,
  `get_entry`, `list_entries`, `get_stats`, `dispute_address`,
  `request_recheck`.
- Admin: `add_chain`, `remove_chain`, `set_ttl_checks`.
- `ttl_checks` default 1000 (same as the other oracles).

## Demos (live-verified by curl, 16 Nov ~23:35 WIB)

| Verdict | Address | Chain | What the API returns |
|---|---|---|---|
| FLAGGED | `0xe8e0960da069c336852246a5bedf18ad05ea25e7` (creator of the fake-USDC honeypot from the Token Safety demos) | 56 | `honeypot_related_address: "1"`, `number_of_malicious_contracts_created: "1"`, `data_source: "GoPlus"` (same on chain 1) |
| NO_FLAGS_FOUND | `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045` (Vitalik) | 1 | every risk flag `"0"`, `data_source: ""` |
| NO_FLAGS_FOUND (BSC, to verify during build) | Vitalik on 56, or a well-known BSC address | 56 | expected all `"0"` — NOT yet checked, verify before the Studio run |

## Honest limits (must go in the README and the submission)

- **The GoPlus dataset has gaps, and one is famous.** The Ronin bridge
  exploiter `0x098B716B8Aaf21512996dC57EB0615e2383E2f96d` returns ALL
  ZEROS on chain 1 and chain 56. GoPlus does not flag one of the most
  famous hacker addresses in crypto. So a NO_FLAGS_FOUND verdict means
  "no flags found in GoPlus", NEVER "proven safe". Say this plainly
  everywhere. (All three peer AIs agreed this is the core weakness.)
- **NO_FLAGS_FOUND is the weak branch.** Most addresses return all
  zeros, including a dead address (`0x000…0001` → all zeros → reads
  NO_FLAGS_FOUND under the rule). A NO_FLAGS_FOUND verdict on an
  address with no history is absence of evidence, not evidence of
  safety. Document it, do not hide it.
- **Rate limits are a proven risk, not a theory.** GoPlus free tier is
  documented at 30 requests/minute (ChatGPT). Token Safety's glsim
  live run already had one transient GoPlus fetch failure during the
  burst, likely a 429. With several validators fetching at once, some
  will get 429 while others get 200, and the contract writes no
  verdict. Test the unauthenticated endpoint under realistic
  validator concurrency before treating no-key as permanent.
- **Single source = consensus is not truth.** Every validator hits the
  same GoPlus endpoint. Agreement proves they got the same answer,
  not that the answer is right. If GoPlus is wrong, down, or changes
  its schema, all validators fail or err together. (All three peer
  AIs said this.) A second independent source for the clean path
  (e.g. a sanctions-list check) would strengthen it — see the
  Sanctions idea under Peer review.
- **Reputation is mutable; verdicts go stale.** A fresh wallet reads
  NO_FLAGS_FOUND at T=0, launches a drainer at T+1, gets flagged at
  T+2. A cached verdict is a snapshot, not a permanent fact. Record
  `checked_at` and consider a wall-clock expiry for NO_FLAGS_FOUND
  (Gemini suggested ~24h; decide at build time).
- **Flags are allegations, not findings.** A FLAGGED verdict stored
  permanently on a public chain is a damaging claim about an address.
  Always present the source and the triggered flags, and never
  describe a provider flag as a judicial finding. (ChatGPT.)
- **Dataset is US/EU-centric** (third-party note on GoPlus coverage):
  sanctions map to OFAC/UK/EU lists; local enforcement lists elsewhere
  are partial.
- **Flags are labels, not proof.** A FLAGGED verdict is a strong
  warning, not a conviction. The contract reports what GoPlus says,
  nothing more.
- **No verdict on fetch failure or disagreement**, by design.

## What this is NOT

- Not a credit score, not a reputation score. No number, no ranking.
  Two verdicts only: FLAGGED or CLEAN.
- Not Token Safety Oracle. That checks token contracts
  (honeypot, taxes, mintable). This checks addresses (people, wallets,
  deployers). A token can be safe while its deployer is flagged, and
  vice versa.
- Not SafeLink. That checks URLs. This checks addresses.
- Not an LLM product. No LLM is called. The GenLayer value is
  independent re-fetching + exact agreement before a shared verdict
  is written.

## Duplicates

- **CLEAR — 16 Nov 23:48 WIB.** Browser check of the GenLayer Project
  Explorer (206 projects: Ecosystem 17, Community 180, Agent Tank 9).
  Keywords searched in all three categories: address (9), reputation
  (22), scam (3), wallet (67), blacklist (0), malicious (0),
  phishing (1), plus an extra GoPlus check (0). Detail pages opened
  for the closest matches (MemeGuard, TweetChecker, AgentScore,
  REPUTRAIL, Doorman; RugBond card checked). No project takes a wallet
  address as input and returns a flagged/clean verdict for scam,
  phishing, honeypot, sanctioned or mixer activity, and none uses
  GoPlus address_security. Limit: not every one of the 67 "wallet" /
  22 "reputation" matches was opened individually — the verdict rests
  on the keyword searches + the closest-match detail checks.
- Closest, all different: AgentScore (agent credit score from Internet
  Court rulings + Sybil-linking, not flagging); MemeGuard (meme-coin
  launchpad, checks a coin's website, not an address); TweetChecker
  (tweet-URL authenticity, not an address); REPUTRAIL (service-history
  reputation for AI agents, not malicious-address flagging); Vouch
  Finance (credit underwriting); Doorman (address as a question seed
  for a community gate); GNS (naming service).

## Slot timing

- Both IC slots THIS week are used (Token Safety + Pool).
- NEXT week (reset Mon 23 Nov 07:00 WIB): Airdrop Eligibility Oracle
  is already queued for one slot. This idea would take the OTHER slot
  next week, or wait for the week after. Decide with Syarif; do not
  assume it displaces the Oracle.

## Peer review — Claude, ChatGPT, Gemini (16 Nov 23:36–23:39 WIB)

Full replies in the user's browser tabs:
- Claude: https://claude.ai/chat/7eb4191a-0fce-49d5-98b4-9b74c7e98540
- ChatGPT: https://chatgpt.com/c/6afb3158-4730-83ec-8fe4-d11aed299bed
- Gemini: https://gemini.google.com/app/51d36f869ab617b2

**Unanimous (all three, independently):**
- CLEAN must go → NO_FLAGS_FOUND / UNFLAGGED. (Applied above.)
- Single-source GoPlus is the core weakness: consensus proves the
  validators got the same answer, not that the answer is true.
- Severity tiers, not one binary flag: critical vs contextual.
  (Applied above: FLAGGED / CAUTION / NO_FLAGS_FOUND.)
- Record the triggered flag list + checked_at; never present a
  provider flag as a judicial finding.

**Each AI's pick for what to build first:**
- Claude → Proxy/Upgradeability Risk Oracle (EIP-1967 storage slots
  via public RPC; IMMUTABLE / UPGRADEABLE / UPGRADEABLE_EOA_ADMIN).
  Raw on-chain reads, no vendor, genuinely distinct, easy demos
  (USDC proxy vs Uniswap v2 core). FEASIBILITY UNVERIFIED: can GenVM
  validators do eth_getStorageAt via a public RPC? Check before
  committing to this one.
- Gemini → DeFi Protocol Security & Audit Oracle (DeFiLlama
  /protocols + /hacks; COMPROMISED / UNAUDITED / AUDITED_ACTIVE).
  DeFiLlama has almost no rate limits; two endpoints joined on the
  protocol slug. DATA CHECK NEEDED: use the single-protocol endpoint
  (/protocol/{slug}), not the giant /protocols list, and verify a
  hacked + an audited demo.
- ChatGPT → Address Reputation itself, with the 3-tier verdicts.
  Fastest: the GoPlus pattern is proven and both demos are live.
  Its roadmap: Address → Stablecoin Depeg → Protocol Health → DAO
  Governance, as composable trust infra.

**Other ideas proposed (one line each):**
- Sanctions Screening Oracle, OFAC SDN list (Claude) — SANCTIONED /
  NOT_LISTED, pure set-membership on a versioned file; caveat: the
  file is large, needs parsing or a mirror. Pairs well with Address
  Reputation as a second source.
- Domain Age Oracle, RDAP (Claude) — NEW / YOUNG / ESTABLISHED;
  complements SafeLink; same bucketing pattern works for Contract /
  Deployer Age.
- Spender & Approval Risk Oracle (Gemini) — HIGH_RISK / CAUTION /
  VERIFIED_SPENDER from GoPlus approval_security + Sourcify. NOTE:
  Gemini cited the Sourcify v1 check-by-addresses URL, which is
  REMOVED — v2 (/v2/contract/{chainId}/{address}) works, verified
  16 Nov.
- DeFi Protocol Health Oracle, TVL trends (ChatGPT) — HEALTHY /
  CAUTION / CRITICAL; limit: TVL drops are not proof of compromise.
- Stablecoin Depeg Oracle (ChatGPT) — PEGGED / WARNING / DEPEGGED /
  SEVERE_DEPEG by deviation. NOTE: close to the banned price-oracle
  family — the distinction (peg status vs price) is thin; think
  carefully before picking this one.
- DAO Governance Integrity Oracle, Snapshot (ChatGPT) — APPROVED /
  REJECTED / PENDING / INVALID; most novel, most complex (DAO-specific
  rules, off-chain votes).
- npm/PyPI Package Registry Oracle (Claude, bonus) — less
  crypto-native.

**Muse's consolidated recommendation:** build Address Reputation
(REVISED 3-tier version) next — it is the only candidate with
live-verified demos both ways + duplicate CLEAR + a proven build
pattern, and it fits next week's open slot after the Airdrop
Eligibility Oracle. Queue Proxy/Upgradeability for the week after,
pending the RPC feasibility check. Do NOT pick Stablecoin Depeg
without resolving the price-oracle overlap first.

## Alternates (why they are #2 and #3, not #1)

### #2 — Contract Source Verification Oracle (Sourcify v2)

- Question: "Is this contract's source code publicly verified?"
- Source: `https://sourcify.dev/server/v2/contract/{chainId}/{address}`
  (v1 API is removed; v2 verified live 16 Nov). Free, no key.
  Returns `match: "match"` / `"partial"` / 404 (no match).
- Verdicts: VERIFIED / PARTIAL / UNVERIFIED. Consensus on match
  status + chain + address.
- Why #2, not #1: the signal is weak. The fake-USDC honeypot
  (Token Safety demo) is Sourcify-verified with a FULL match
  (verified 2026-09-10). Verified source does not mean safe, so the
  verdict answers a narrower question and is easy to misread.
  UNVERIFIED demo also not yet found (needs a real contract with no
  Sourcify match — not yet verified live).

### #3 — Holder Concentration Oracle (GoPlus holders)

- Question: "Is this token's supply concentrated in a few wallets?"
- Source: GoPlus token_security `holders` array (top holders with
  `percent` as a decimal fraction; WBNB top holder 0.1333 = 13.3%).
  Same provider as Token Safety, already proven.
- Verdicts could be DISPERSED / CONCENTRATED on a top-10 combined
  share threshold.
- Why #3, not #1: the data is noisy and the demo is unproven. The
  fake-USDC top-5 percents are tiny fractions (~0.00006) that do not
  demonstrate concentration, and no verified concentrated demo exists
  yet. Needs a careful rule + a verified whale demo before it is a
  real design. Same API as Token Safety, so it also reads as a
  smaller step than a new question.

## Build checklist (same pipeline as Token Safety / Pool)

- [x] Duplicate check CLEAR (16 Nov 23:48 WIB, 206 projects).
- [x] Peer review done (Claude, ChatGPT, Gemini, 16 Nov 23:36–23:39 WIB);
      verdict rule revised to 3-tier (FLAGGED / CAUTION / NO_FLAGS_FOUND).
- [ ] Build contracts + tests (stub + GenVM direct), run test suites 2x
      per Syarif's submit rule.
- [ ] glsim live consensus (leader + 5 validators, real GoPlus fetches).
- [ ] Studio deploy to stable Studionet + live runs (FLAGGED + CAUTION
      if a CAUTION demo is found + NO_FLAGS_FOUND).
- [ ] GitHub repo (Syarif creates) + push.
- [ ] Portal IC submit (plain-style text from the start, no em-dash
      anywhere including the title).

## Correction — 25 Nov 2026 (build time)

Two claims in this doc were wrong and are corrected here. The
contract, README, and submission draft all use the corrected facts.

1. **The Ronin exploiter address had a typo.** This doc wrote
   `0x098B716B8Aaf21512996dC57EB0615e2383E2f96d` (41 hex chars). The
   real address is `0x098B716B8Aaf21512996dC57EB0615e2383E2f96`
   (40 hex chars, Etherscan: "Ronin Bridge Exploiter"). The typo'd
   address fails the contract's own address validation.
2. **GoPlus DOES flag the Ronin exploiter.** This doc claimed the
   exploiter "returns ALL ZEROS" and used it as the headline dataset
   gap. That was measured against the typo'd address, which GoPlus
   answers with all zeros without validating length. Re-fetched with
   the correct address on 25 Nov 2026: `sanctioned: "1"`,
   `stealing_attack: "1"`, `blacklist_doubt: "1"`,
   `data_source: "SlowMist,BlockSec"` — verdict FLAGGED. The Ronin
   demo is now a second live FLAGGED demo, not a NO_FLAGS_FOUND
   honest-limit demo. The general single-source and dataset-gap
   limits still stand, but the false Ronin example must not be
   repeated anywhere.

Other corrections from the build: Vitalik on BSC 56 verified live
(all zeros, NO_FLAGS_FOUND); chain 8453 verified working for
address_security; no live CAUTION demo address found after four
plausible candidates; no live UNCHECKED case exists for
address_security (every query answers code 1 with a full flag set).
