# Address Reputation Oracle

**Question:** is this address safe to interact with?

Everyone asks it before sending money to an unfamiliar address:
airdrop hunters, OTC traders, anyone who got a wallet address in a
DM. Today the answer is a manual lookup on a block explorer or a
security site. This contract turns it into a shared,
consensus-checked verdict.

This is the other half of the Token Safety Oracle. That one asks "is
this token safe to buy". This one asks "is this address safe to deal
with". Same audience, different question, no overlap with the other
oracles (SafeLink = URLs, Token Safety = token contracts, Pool
Liquidity = DEX pools, Airdrop Eligibility = claim lists).

## How it works

1. Anyone calls `check_address(chain_id, address)`.
2. The leader fetches the address record from the GoPlus
   address-security API (free, no key):
   `https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id={chain_id}`
3. Every validator independently re-fetches the same URL and
   re-derives the same flags.
4. A verdict is written ONLY when all validators agree exactly on the
   compared signal fields. Disagreement means no write (the
   transaction goes undetermined). A fetch failure, a non-200 status,
   a non-OK GoPlus code, an empty result, an unparseable body, or a
   missing/malformed flag also writes nothing.

The verdict is a DETERMINISTIC rule over GoPlus flags. No LLM is
called anywhere in v1. The GenLayer value is independent re-fetching
plus exact agreement before a shared verdict is written.

## Verdicts

| Verdict | Rule |
|---|---|
| `flagged` | Any CRITICAL flag is `"1"`, or `number_of_malicious_contracts_created` is greater than `"0"` |
| `caution` | No critical finding, but at least one CONTEXTUAL flag is `"1"` |
| `no_flags_found` | Every flag is `"0"` and the count is `0` |
| `unchecked` | The source could not be fetched or parsed. No verdict is written for this case |

CRITICAL flags: `sanctioned`, `money_laundering`, `cybercrime`,
`phishing_activities`, `stealing_attack`, `financial_crime`,
`honeypot_related_address`, `number_of_malicious_contracts_created`
(a count string, not a `"0"`/`"1"` flag).

CONTEXTUAL flags: `mixer`, `gas_abuse`, `darkweb_transactions`,
`blacklist_doubt`, `fake_kyc`, `fake_standard_interface`,
`fake_token`, `blackmail_activities`, `malicious_mining_activities`,
`reinit`.

`no_flags_found` means only "the provider reported no known
indicators at check time". It is NEVER "proven safe". See Honest
limits below.

Compared fields (consensus = exact agreement on all of these):
`chain_id`, `address` (lowercase), every risk flag above as a string,
`status_code`, `source_url`. `contract_address` and `data_source` are
recorded for audit but NEVER compared: `contract_address` is
unreliable (an EOA, Vitalik included, returns `"1"` for it), and
`data_source` varies per address (`"GoPlus"` for flagged addresses,
`""` for clean ones, `"SlowMist,BlockSec"` for the Ronin exploiter)
and adds no verdict signal.

The `chain_id` query parameter is REQUIRED: without it GoPlus still
answers code 1 but every flag reads `"0"`, even for known-bad
addresses (verified live 25 Nov 2026).

## API

- `check_address(chain_id, address)` — check an address; writes a
  verdict on consensus, or returns a fresh cached entry without a new
  consensus round. Disputed entries always re-check.
- `get_verdict(chain_id, address)` / `get_entry(chain_id, address)` —
  read a stored verdict (`unchecked` when nothing is stored).
- `is_safe(chain_id, address)` — true only for a fresh
  `no_flags_found` verdict. "Safe" here means exactly "GoPlus
  reported no known indicators at check time", NOT "proven safe".
- `list_entries(offset, limit)` — newest first, max 100 per call.
- `list_chains()` — supported chains (v1: 1, 56, 8453).
- `get_stats()` — totals and counters.
- `dispute_address(chain_id, address, reason)` — mark an entry
  disputed so the next check re-fetches.
- `request_recheck(chain_id, address)` — same, reason "recheck
  requested".
- Admin (deployer only): `add_chain(chain_id)`,
  `remove_chain(chain_id)` (tombstone, never a physical remove),
  `set_ttl_checks(ttl)`. `ttl_checks` default 1000 (count-based
  freshness: an entry is fresh while fewer than `ttl_checks` checks
  have happened since it was written).

## Demos (all live-verified by curl, 25 Nov 2026)

| Verdict | Address | Chain | What GoPlus returns |
|---|---|---|---|
| FLAGGED | `0xe8e0960da069c336852246a5bedf18ad05ea25e7` (creator of the fake-USDC honeypot from the Token Safety demos) | 56 | `honeypot_related_address: "1"`, `number_of_malicious_contracts_created: "1"`, `data_source: "GoPlus"` |
| FLAGGED | `0x098b716b8aaf21512996dc57eb0615e2383e2f96` (Ronin bridge exploiter) | 1 | `sanctioned: "1"`, `stealing_attack: "1"`, `blacklist_doubt: "1"`, `data_source: "SlowMist,BlockSec"` |
| NO_FLAGS_FOUND | `0xd8da6bf26964af9d7eed9e03e53415d37aa96045` (Vitalik) | 1 | every risk flag `"0"`, `data_source: ""` |
| NO_FLAGS_FOUND | Vitalik | 56 | every risk flag `"0"` (verified live, was an open item in DESIGN.md) |

No live CAUTION demo address was found (four plausible candidates,
including Tornado Cash pool/router addresses, all returned all zeros
on 25 Nov 2026). The CAUTION branch is covered by stub and GenVM
direct tests with a synthetic body built from the real Vitalik record.
A real CAUTION demo is still an open item.

## Honest limits (read before trusting a verdict)

- **NO_FLAGS_FOUND is absence of evidence, not evidence of safety.**
  Most addresses return all zeros, including a dead address
  (`0x000...0001` reads all zeros). A NO_FLAGS_FOUND verdict on an
  address with no history means "GoPlus knows nothing bad about it",
  nothing more. Never present it as "proven safe".
- **The Ronin example in DESIGN.md v1 was wrong, and it is corrected
  here.** The design doc claimed GoPlus returns all zeros for the
  Ronin exploiter. That was measured against a typo'd 41-character
  address. The real address IS flagged (sanctioned, stealing_attack,
  blacklist_doubt). Do not repeat the old claim anywhere.
- **Rate limits are a proven risk, not a theory.** GoPlus free tier is
  documented at 30 requests/minute. Token Safety's glsim live run
  already had one transient GoPlus fetch failure during the burst,
  likely a 429. With several validators fetching at once, some will
  get 429 while others get 200, and the contract writes no verdict.
  Test the unauthenticated endpoint under realistic validator
  concurrency before treating no-key as permanent.
- **Single source = consensus is not truth.** Every validator hits
  the same GoPlus endpoint. Agreement proves they got the same
  answer, not that the answer is right. If GoPlus is wrong, down, or
  changes its schema, all validators fail or err together. A second
  independent source for the clean path (e.g. a sanctions-list check)
  would strengthen it.
- **Reputation is mutable; verdicts go stale.** A fresh wallet reads
  NO_FLAGS_FOUND at T=0, launches a drainer at T+1, gets flagged at
  T+2. A cached verdict is a snapshot, not a permanent fact. Each
  entry records its check sequence; freshness is count-based
  (`ttl_checks`, default 1000 checks), not wall-clock. A wall-clock
  expiry for NO_FLAGS_FOUND (about 24h was suggested in review) was
  NOT built: GenVM v0.2.5 exposes no reliable wall-clock here, and
  the count-based design is kept as specified. Noted as an open item.
- **Flags are allegations, not findings.** A FLAGGED verdict stored
  permanently on a public chain is a damaging claim about an address.
  The entry always records the source and the triggered flags, and a
  provider flag is never described as a judicial finding.
- **Dataset is US/EU-centric.** Sanctions map to OFAC/UK/EU lists;
  local enforcement lists elsewhere are partial.
- **Flags are labels, not proof.** A FLAGGED verdict is a strong
  warning, not a conviction. The contract reports what GoPlus says,
  nothing more.
- **No verdict on fetch failure or disagreement**, by design.

## What this is NOT

- Not a credit score, not a reputation score. No number, no ranking.
- Not the Token Safety Oracle. That checks token contracts (honeypot,
  taxes, mintable). This checks addresses (people, wallets,
  deployers). A token can be safe while its deployer is flagged, and
  vice versa.
- Not SafeLink. That checks URLs. This checks addresses.
- Not an LLM product. No LLM is called. The GenLayer value is
  independent re-fetching + exact agreement before a shared verdict
  is written.
- Not a price oracle, not a liquidity oracle. It says nothing about
  price, depth, or future owner actions.

## Anti-rejection notes (the Token Safety lesson)

The Token Safety Oracle v1 submission was REJECTED by the Portal
steward with E018: its `chains` storage map used `u64` as a TreeMap
key, and the target check reports E018 because that key type is
unsupported. This contract was built with that lesson applied from
the start:

- Every TreeMap in `contracts/address_reputation_oracle.py` is keyed
  by `str` ONLY. `chains` uses `str(chain_id)` keys; `entries` uses
  `"chain|address"` string keys. `tests/test_contract_sync.py`
  includes a scan that fails the build if any TreeMap key type is not
  `str`.
- No other `u64`-keyed map exists anywhere in the contract. (`u64`
  is still used for fields, parameters, and `DynArray` values, which
  E018 does not cover.)
- The pure logic in `contracts/address_reputation_logic.py` is
  byte-identical (AST-identical) to the copies in the contract file;
  `tests/test_contract_sync.py` fails the build if they drift.

## Tests

- Stub suite (`tests/`, fake genlayer module, no GenVM):
  `../../genlayer-intelligent-contracts-submission/safelink/.venv/bin/python -m pytest tests -q`
  — 87 tests, run twice green.
- GenVM direct tests (`tests-direct/`, real contract under the gltest
  direct engine, web mocked with REAL GoPlus response bytes fetched
  live 25 Nov 2026 and saved at `tests-direct/fixtures/`):
  `../../genlayer-intelligent-contracts-submission/safelink/.venv/bin/gltest tests-direct -q`
  — 10 tests, run twice green.
- glsim live consensus (`scripts/glsim_live_test.py`, fresh glsim
  server on :4000, leader + 5 validators fetching LIVE GoPlus):
  5/5 checks passed, twice, on two fresh servers. See TEST_LOG.md.
  CAUTION has no live demo, so the live run covers FLAGGED x2 and
  NO_FLAGS_FOUND x2 plus deploy defaults; the no-verdict branches are
  covered by stub + direct tests.

## Files

- `contracts/address_reputation_oracle.py` — the contract (pins the
  stable runner `py-genlayer:1jb45aa8…` v0.2.5).
- `contracts/address_reputation_logic.py` — pure logic, stdlib only,
  unit-tested with plain pytest.
- `DESIGN.md` — the full design, peer review, and duplicate check
  (CLEAR, 16 Nov 2026, 206 projects in the Explorer).
- `TEST_LOG.md` — full run history.
- `SUBMISSION_DRAFT.md` — Portal submission draft (plain style).

## Status

Built and verified 25 Nov 2026. NOT yet deployed to Studio, NOT yet
pushed to GitHub, NOT yet submitted to the Portal. Those steps are
separate and need the deployer (Studio) and the repo owner (Syarif).
