# TEST_LOG — Address Reputation Oracle

## 2026-11-25 ~17:25 WIB — build (first pass)

- Read DESIGN.md + the Token Safety / Pool Liquidity templates and
  mirrored their proven patterns (storage, validators, consensus,
  test layout). Same build constants: stable Studionet chain 61999,
  runner pin `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`
  (v0.2.5), SDK py-genlayer 0.2.16, `Response` fields
  `.status`/`.headers`/`.body`, `@allow_storage` structs, `UserError`
  from `genlayer.gl.vm` (never `gl.UserError`).
- Anti-E018 design from the start: every TreeMap keyed by `str` only
  (`chains` uses `str(chain_id)`, `entries` uses `"chain|address"`).
  `tests/test_contract_sync.py` adds a scan that fails the build on
  any non-`str` TreeMap key.
- One rule stricter than the Token Safety precedent, from DESIGN.md:
  missing, null, or malformed flags mean NO verdict (parse_ok False),
  not "". A binary flag must be exactly "0" or "1"; the
  malicious-contracts count must parse as a non-negative integer
  string. A safety oracle fails closed, never by guessing.
- Chains v1: {1, 56, 8453} per DESIGN.md line 56. (The build brief
  summarized this as {1, 56}; DESIGN.md is the spec and says
  {1, 56, 8453}, and chain 8453 was verified live working for
  address_security on 25 Nov 2026.)

## 2026-11-25 ~17:30 WIB — live demo verification (curl, GoPlus)

- FLAGGED demo CONFIRMED: fake-USDC creator
  `0xe8e0960da069c336852246a5bedf18ad05ea25e7` on BSC 56 returns
  `honeypot_related_address: "1"`,
  `number_of_malicious_contracts_created: "1"`,
  `data_source: "GoPlus"`.
- NO_FLAGS_FOUND demos CONFIRMED: Vitalik
  `0xd8da6bf26964af9d7eed9e03e53415d37aa96045` on Eth 1 and on BSC 56,
  all flags `"0"`. (Vitalik-on-BSC was an open item in DESIGN.md;
  now verified.)
- `chain_id` REQUIRED, re-confirmed: the same Vitalik query WITHOUT
  `chain_id` still answers code 1 but every flag reads `"0"`. The
  contract always passes `chain_id`.
- `contract_address` unreliability re-confirmed: Vitalik (an EOA)
  returns `contract_address: "1"`. It stays excluded from compared
  fields, per DESIGN.md.
- Dead address `0x000...0001` returns all zeros on Eth 1, so it
  reads NO_FLAGS_FOUND under the rule (absence of evidence, not
  proof of safety).
- Chain 8453 works for address_security (Vitalik all zeros, code 1).
- Even an unsupported chain (999999) answers code 1 with all zeros,
  so there is NO live UNCHECKED demo for address_security: every
  query returns a full flag set. The no-verdict branches are covered
  by stub + direct tests only.
- CAUTION demo: NOT FOUND. Four plausible candidates (Tornado Cash
  pool/router addresses) all returned all zeros. The CAUTION branch
  is covered by stub + direct tests with a synthetic body built from
  the real Vitalik record (mixer flipped to "1"). A real CAUTION demo
  address is still an open item.

## 2026-11-25 ~17:40 WIB — Ronin address correction (important)

- The stub suite caught it: DESIGN.md's Ronin exploiter address
  `0x098B716B8Aaf21512996dC57EB0615e2383E2f96d` is 41 hex chars, not
  40. It fails the contract's own address validation.
- Verified against Etherscan search results: the real address is
  `0x098B716B8Aaf21512996dC57EB0615e2383E2f96` (ends `...e2383E2f96`,
  no trailing `d`). Etherscan labels it "Ronin Bridge Exploiter".
- Re-fetched GoPlus with the CORRECT address: `sanctioned: "1"`,
  `stealing_attack: "1"`, `blacklist_doubt: "1"`,
  `data_source: "SlowMist,BlockSec"`. The verdict is FLAGGED.
- Consequence: DESIGN.md's claim "the Ronin exploiter returns all
  zeros" is WRONG. It was measured against the typo'd address, which
  GoPlus answers with all zeros without validating length. The Ronin
  demo is now a second live FLAGGED demo, and the old all-zeros claim
  must not be repeated in the README or the submission. The general
  single-source / dataset-gap limits still stand, but without the
  false Ronin example. All fixtures, tests, and the glsim script were
  updated to the correct address and the FLAGGED expectation. A
  correction note was appended to DESIGN.md.

## 2026-11-25 ~17:45 WIB — stub suite (tests/)

- First run: 73 passed, 14 failed. Two real bugs found:
  1. `triggered_flags` appended the count flag last instead of
     following FLAG_KEYS order (critical, count, contextual).
     Fixed in both the logic module and the contract copy.
  2. The conftest demo addresses were written in EIP-55 mixed case
     (Vitalik, Ronin) while the contract normalizes to lowercase, so
     the stub's canned GoPlus URLs (seeded with the mixed-case form)
     never matched the fetched lowercase URL and every check 404'd.
     Fixed by defining all demo addresses lowercase in conftest.
- Second run: **87 passed, 0 failed.**
- Third run (second green run per the submit rule): **87 passed,
  0 failed.**
- Coverage: normalize/validate/render URL, all 7 critical flags
  individually, count-only flagged (1 and 12), flagged-beats-caution,
  all 10 contextual flags individually, triggered_flags order,
  derive for every demo + every failure shape (empty result, system
  error code, non-200, malformed JSON, result not a dict, wrong code,
  missing flag, malformed flag, bad count), contract admin/chains,
  caching, disputes, recheck counters, validator disagreement.

## 2026-11-25 ~17:50 WIB — GenVM direct tests (tests-direct/)

- First run: **10 passed, 0 failed.**
- Second run: **10 passed, 0 failed.**
- Real contract under the gltest direct engine (SDK v0.2.16 pinned),
  web mocked with REAL GoPlus response bytes fetched live 25 Nov 2026
  (`tests-direct/fixtures/goplus-*.json`): Vitalik Eth + BSC
  NO_FLAGS_FOUND with validator agreement, fake-USDC creator FLAGGED
  with validator agreement, Ronin FLAGGED with validator agreement,
  synthetic CAUTION with validator agreement, missing-flag body
  writes nothing, validator disagreement detected (body flipped),
  fetch 404 writes nothing, unknown chain rejected.

## 2026-11-25 ~18:00 WIB — glsim LIVE consensus (scripts/)

- Fresh glsim server on :4000 with sanitized `no_proxy`/`NO_PROXY`
  (`localhost,127.0.0.1,198.19.0.1,198.19.0.2`; the sandbox default
  contains bracketed IPv6 entries that break httpcore, per the Token
  Safety 16 Nov notes). Egress proxy mandatory.
- Run 1 (fresh server): **5/5 passed.** Deployed at
  `0x5307f5d1ed273b97225fec80eb739345fbfc063c` (local sim only).
  - deploy_defaults PASS
  - flagged_creator_live_flagged PASS (4.7s), triggered
    `honeypot_related_address,number_of_malicious_contracts_created`
  - vitalik_eth_live_no_flags PASS (7.1s)
  - vitalik_bsc_live_no_flags PASS (4.2s)
  - ronin_live_flagged PASS (4.2s), triggered
    `sanctioned,stealing_attack,blacklist_doubt`
  - Final stats: check_count 4, flagged 2, no_flags_found 2,
    total_entries 4, total_disputes 0, ttl_checks 1000.
- Run 2 (second fresh server, per the two-runs rule): **5/5 passed.**
  Deployed at `0x1ac51e9561063a693d42f382958a65d8b04a24f9`
  (local sim only). Same verdicts, 3.7–5.3s per check. Result file
  `scripts/glsim_live_result.json` holds run 2.
- CAUTION was not covered live (no live demo address exists); the
  branch is covered by stub + direct tests. No live UNCHECKED case
  exists for address_security (see above); those branches are covered
  by stub + direct tests.

## Still open

- Studio deploy to stable Studionet + live runs there (parent).
- GitHub repo (Syarif creates; name not decided yet) + push (parent).
- Portal IC submission (parent; draft in SUBMISSION_DRAFT.md).
- Real CAUTION demo address (none found live yet).
- NO_FLAGS_FOUND wall-clock expiry (~24h suggested in review): NOT
  built. The count-based `ttl_checks` design is kept as specified;
  GenVM v0.2.5 exposes no reliable wall-clock here.
- GoPlus free-tier rate limits under real validator concurrency
  (30 req/min documented): untested at scale; the contract fails
  closed (no verdict) on 429s, which is the safe direction.
