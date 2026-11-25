# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""Address Reputation Oracle — is address A on chain C safe to deal with?

One contract, any EVM address with GoPlus security data. Any account
can ask the contract to check an address; the leader fetches the
address's GoPlus address-security record, every validator
independently re-fetches it and re-derives the same flags, and a
verdict is written ONLY when they agree exactly on the compared signal
fields. Disagreement means no write (the transaction goes
undetermined) — a verdict is never written on one node's word alone,
and an address is never marked clean on disagreement.

The verdict is a DETERMINISTIC rule over GoPlus flags (see
verdict_from_signals). No LLM is called anywhere in v1: address
reputation here is checkable facts (sanctioned, phishing, mixer,
honeypot-related, malicious contracts created), not an LLM opinion.
That is the whole point of the primitive — the same address checked
twice gives the same verdict, and any reviewer can re-derive it by
hand from the stored evidence.

NO_FLAGS_FOUND means only "the provider reported no known indicators
at check time". It is NEVER "proven safe": GoPlus has dataset gaps
(the Ronin bridge exploiter returns all zeros), most addresses return
all zeros, and a fresh wallet can turn malicious after the check. The
submission and the README state this plainly.

Target: stable Studionet, GenVM runner py-genlayer v0.2.5
(1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6) — same as
SafeLink, the Token Safety Oracle, and the Pool Liquidity Oracle. Do
NOT deploy this file to Studio-dev / v0.6 without re-pinning the
header.

The pure functions below (normalize_address, validate_chain_id,
render_source_url, _parse_count, _flag_value, _flags_well_formed,
derive_signals, triggered_flags, verdict_from_signals) are
byte-identical copies of contracts/address_reputation_logic.py, which
is unit-tested with plain pytest. They are duplicated here because a
single-file GenLayer contract cannot import a sibling module on-chain.
tests/test_contract_sync.py fails the build if the copies drift.

Anti-rejection note (E018, the Token Safety Oracle lesson): every
TreeMap in this contract is keyed by str ONLY. The chains map uses
str(chain_id) keys, never u64 — GenVM lint rejects u64 TreeMap keys
and the Portal steward rejected the Token Safety submission for
exactly that. The entries map is keyed by "chain|address" strings.
"""

import json

from genlayer import *

GOPLUS_BASE_URL = "https://api.gopluslabs.io/api/v1/address_security"

ALLOWED_CHAINS = (1, 56, 8453)

VERDICT_FLAGGED = "flagged"
VERDICT_CAUTION = "caution"
VERDICT_NO_FLAGS = "no_flags_found"
VERDICT_UNCHECKED = "unchecked"

# GoPlus address-security risk flags. CRITICAL flags alone force
# FLAGGED; CONTEXTUAL flags alone force CAUTION. The count field is a
# string holding a non-negative integer, not a "0"/"1" flag.
CRITICAL_FLAGS = (
    "sanctioned",
    "money_laundering",
    "cybercrime",
    "phishing_activities",
    "stealing_attack",
    "financial_crime",
    "honeypot_related_address",
)

COUNT_FLAG = "number_of_malicious_contracts_created"

CONTEXTUAL_FLAGS = (
    "mixer",
    "gas_abuse",
    "darkweb_transactions",
    "blacklist_doubt",
    "fake_kyc",
    "fake_standard_interface",
    "fake_token",
    "blackmail_activities",
    "malicious_mining_activities",
    "reinit",
)

# All compared flag fields, in DESIGN.md order (critical, count,
# contextual).
FLAG_KEYS = CRITICAL_FLAGS + (COUNT_FLAG,) + CONTEXTUAL_FLAGS

# Signal fields the validator must agree on exactly. Everything else in
# the signals dict is observation only. All compared values are strings.
COMPARED_SIGNAL_KEYS = (
    ("chain_id", "address") + FLAG_KEYS + ("status_code", "source_url")
)

BODY_SAMPLE_LEN = 200

_HEX = "0123456789abcdef"

DEFAULT_TTL_CHECKS = 1000
MAX_LIST_LIMIT = 100


def normalize_address(raw_address):
    """Normalize a wallet address into its canonical registry key.

    Lower-case ``0x`` + 40 hex chars. Raises ValueError on anything
    else. The contract converts this to UserError.
    """
    if not isinstance(raw_address, str):
        raise ValueError("address must be a string")
    address = raw_address.strip().lower()
    if not address.startswith("0x"):
        raise ValueError("address must start with 0x")
    if len(address) != 42:
        raise ValueError("address must be 0x + 40 hex chars")
    for ch in address[2:]:
        if ch not in _HEX:
            raise ValueError("address contains a non-hex character")
    return address


def validate_chain_id(chain_id):
    """Validate a chain id against the v1 allowlist {1, 56, 8453}.

    Returns the chain id unchanged. Raises ValueError on anything
    else (non-int, bool, or a chain outside the allowlist). The
    contract converts this to UserError.
    """
    if isinstance(chain_id, bool) or not isinstance(chain_id, int):
        raise ValueError("chain_id must be an int")
    if chain_id not in ALLOWED_CHAINS:
        raise ValueError("chain_id not supported in v1: " + str(chain_id))
    return chain_id


def render_source_url(chain_id, address):
    """Render the GoPlus address-security URL for a (chain, address) pair.

    Both inputs are validated (chain allowlist, address shape) and the
    address is normalized to lower-case. The chain_id query parameter
    is REQUIRED: without it GoPlus still answers code 1 but every flag
    reads "0", even for known-bad addresses. Raises ValueError on
    invalid inputs.
    """
    chain_id = validate_chain_id(chain_id)
    address = normalize_address(address)
    return (
        GOPLUS_BASE_URL
        + "/"
        + address
        + "?chain_id="
        + str(chain_id)
    )


def _parse_count(raw):
    """Parse the malicious-contracts count string to an int or None.

    Must be a string of digits ("0", "1", "12"). Anything else returns
    None — the caller treats None as "cannot prove the count", never
    as 0.
    """
    if raw is None or not isinstance(raw, str):
        return None
    if raw == "" or not raw.isdigit():
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def _flag_value(entry, key):
    """Read one compared flag from a GoPlus result entry as a string.

    GoPlus returns strings; a missing field or a null compares as "".
    Any other JSON value is stringified defensively.
    """
    value = entry.get(key, "")
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _flags_well_formed(entry):
    """Check every compared flag is present and well-formed.

    Binary flags must be exactly "0" or "1"; the count flag must parse
    as a non-negative integer string. Missing, null, or malformed
    indicators mean the record cannot be trusted as a verdict basis.
    """
    for key in CRITICAL_FLAGS + CONTEXTUAL_FLAGS:
        value = entry.get(key)
        if value not in ("0", "1"):
            return False
    count = _parse_count(entry.get(COUNT_FLAG))
    if count is None:
        return False
    return True


def derive_signals(chain_id, address, source_url, status_code, body):
    """Derive the check signals for one fetched GoPlus response.

    ``chain_id`` / ``address`` must already be normalized, ``body`` is
    the decoded response text. Runs identically on leader and
    validator; the validator compares exactly the COMPARED_SIGNAL_KEYS
    fields of the result. A non-200 status, a non-OK GoPlus code, an
    empty result, an unparseable body, or a missing/malformed flag
    yields ``parse_ok`` False — the contract treats that as a failed
    fetch and writes nothing.
    """
    signals = {
        "chain_id": str(chain_id),
        "address": address,
        "source_url": source_url,
        "status_code": str(status_code),
        "parse_ok": False,
        # Observation only — recorded for audit, never compared.
        "content_len": len(body),
        "body_sample": body[:BODY_SAMPLE_LEN],
        "data_source": "",
        "triggered_flags": "",
        "flag_count": 0,
    }
    for key in FLAG_KEYS:
        signals[key] = ""
    if status_code != 200:
        return signals
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return signals
    if not isinstance(data, dict):
        return signals
    if data.get("code") not in (1, "1"):
        return signals
    result = data.get("result")
    if not isinstance(result, dict):
        return signals
    if not result:
        return signals
    if not _flags_well_formed(result):
        return signals
    for key in FLAG_KEYS:
        signals[key] = _flag_value(result, key)
    signals["data_source"] = _flag_value(result, "data_source")
    triggered = triggered_flags(signals)
    signals["triggered_flags"] = ",".join(triggered)
    signals["flag_count"] = len(triggered)
    signals["parse_ok"] = True
    return signals


def triggered_flags(signals):
    """List the flags that are positive in a signals dict, in order.

    Follows FLAG_KEYS order (critical, count, contextual). A binary
    flag counts when it is "1"; the count flag counts when it parses
    to an integer greater than 0.
    """
    triggered = []
    for key in FLAG_KEYS:
        if key == COUNT_FLAG:
            count = _parse_count(signals.get(key))
            if count is not None and count > 0:
                triggered.append(key)
        elif signals.get(key) == "1":
            triggered.append(key)
    return triggered


def verdict_from_signals(signals):
    """Deterministic verdict rule. Pure function of the signals dict.

    flagged: any CRITICAL flag is "1", or the malicious-contracts
        count is greater than 0.
    caution: no critical finding, but at least one CONTEXTUAL flag
        is "1".
    no_flags_found: every flag is "0" and the count is 0. This means
        only "the provider reported no known indicators at check
        time" — NEVER "proven safe".
    unchecked: the source could not be fetched or parsed — no verdict
        is written for this case.
    """
    if not signals["parse_ok"]:
        return VERDICT_UNCHECKED
    for key in CRITICAL_FLAGS:
        if signals[key] == "1":
            return VERDICT_FLAGGED
    count = _parse_count(signals[COUNT_FLAG])
    if count is not None and count > 0:
        return VERDICT_FLAGGED
    for key in CONTEXTUAL_FLAGS:
        if signals[key] == "1":
            return VERDICT_CAUTION
    return VERDICT_NO_FLAGS


from genlayer import allow_storage
from genlayer.gl.vm import UserError


@allow_storage
class Entry:
    """One address reputation verdict. Stored as the value of TreeMap[str, Entry]."""

    chain_id: u64
    address: str
    verdict: str
    sanctioned: str
    money_laundering: str
    cybercrime: str
    phishing_activities: str
    stealing_attack: str
    financial_crime: str
    honeypot_related_address: str
    number_of_malicious_contracts_created: str
    mixer: str
    gas_abuse: str
    darkweb_transactions: str
    blacklist_doubt: str
    fake_kyc: str
    fake_standard_interface: str
    fake_token: str
    blackmail_activities: str
    malicious_mining_activities: str
    reinit: str
    triggered_flags: str
    flag_count: u64
    data_source: str
    source_url: str
    status_code: u64
    checked_seq: u64
    disputes: u64
    last_dispute_reason: str
    disputed: bool

    def __init__(
        self,
        chain_id=0,
        address="",
        verdict="unchecked",
        sanctioned="",
        money_laundering="",
        cybercrime="",
        phishing_activities="",
        stealing_attack="",
        financial_crime="",
        honeypot_related_address="",
        number_of_malicious_contracts_created="",
        mixer="",
        gas_abuse="",
        darkweb_transactions="",
        blacklist_doubt="",
        fake_kyc="",
        fake_standard_interface="",
        fake_token="",
        blackmail_activities="",
        malicious_mining_activities="",
        reinit="",
        triggered_flags="",
        flag_count=0,
        data_source="",
        source_url="",
        status_code=0,
        checked_seq=0,
        disputes=0,
        last_dispute_reason="",
        disputed=False,
    ):
        self.chain_id = chain_id
        self.address = address
        self.verdict = verdict
        self.sanctioned = sanctioned
        self.money_laundering = money_laundering
        self.cybercrime = cybercrime
        self.phishing_activities = phishing_activities
        self.stealing_attack = stealing_attack
        self.financial_crime = financial_crime
        self.honeypot_related_address = honeypot_related_address
        self.number_of_malicious_contracts_created = (
            number_of_malicious_contracts_created
        )
        self.mixer = mixer
        self.gas_abuse = gas_abuse
        self.darkweb_transactions = darkweb_transactions
        self.blacklist_doubt = blacklist_doubt
        self.fake_kyc = fake_kyc
        self.fake_standard_interface = fake_standard_interface
        self.fake_token = fake_token
        self.blackmail_activities = blackmail_activities
        self.malicious_mining_activities = malicious_mining_activities
        self.reinit = reinit
        self.triggered_flags = triggered_flags
        self.flag_count = flag_count
        self.data_source = data_source
        self.source_url = source_url
        self.status_code = status_code
        self.checked_seq = checked_seq
        self.disputes = disputes
        self.last_dispute_reason = last_dispute_reason
        self.disputed = disputed


@allow_storage
class AddressReputationOracle(gl.Contract):
    admin: Address
    # Chain allowlist: True = checks allowed. Removal is a tombstone
    # (False), never a physical remove — mirrors the Token Safety
    # Oracle's disabled-chain pattern.
    # Keys are str(chain_id), NOT u64: GenVM lint (E018) rejects u64
    # TreeMap keys — the Portal steward rejected the Token Safety
    # Oracle v1 submission for exactly this. list_chains converts
    # back to int.
    chains: TreeMap[str, bool]
    chain_order: DynArray[str]
    entries: TreeMap[str, Entry]
    entry_order: DynArray[str]
    check_count: u64
    flagged_count: u64
    caution_count: u64
    no_flags_count: u64
    total_disputes: u64
    ttl_checks: u64

    def __init__(self):
        self.admin = gl.message.sender_address
        self.check_count = 0
        self.flagged_count = 0
        self.caution_count = 0
        self.no_flags_count = 0
        self.total_disputes = 0
        self.ttl_checks = DEFAULT_TTL_CHECKS
        for chain_id in ALLOWED_CHAINS:
            self.chains[str(chain_id)] = True
            self.chain_order.append(str(chain_id))

    # -- internal helpers (deterministic, no nondet calls) ------------

    def _require_admin(self):
        if gl.message.sender_address != self.admin:
            raise UserError("Address Reputation Oracle: only admin")

    def _normalize_address_or_raise(self, raw_address: str) -> str:
        try:
            return normalize_address(raw_address)
        except ValueError as exc:
            raise UserError(
                "Address Reputation Oracle: invalid address: " + str(exc)
            )

    def _validate_chain_or_raise(self, chain_id: u64) -> u64:
        try:
            return validate_chain_id(chain_id)
        except ValueError as exc:
            raise UserError(
                "Address Reputation Oracle: invalid chain_id: " + str(exc)
            )

    def _entry_key(self, chain_id: u64, address: str) -> str:
        return str(chain_id) + "|" + address

    def _is_fresh(self, entry: Entry) -> bool:
        if entry.disputed:
            return False
        return (self.check_count - entry.checked_seq) < self.ttl_checks

    def _increment_counter(self, verdict: str):
        if verdict == VERDICT_FLAGGED:
            self.flagged_count += 1
        elif verdict == VERDICT_CAUTION:
            self.caution_count += 1
        elif verdict == VERDICT_NO_FLAGS:
            self.no_flags_count += 1

    def _decrement_counter(self, verdict: str):
        if verdict == VERDICT_FLAGGED and self.flagged_count > 0:
            self.flagged_count -= 1
        elif verdict == VERDICT_CAUTION and self.caution_count > 0:
            self.caution_count -= 1
        elif verdict == VERDICT_NO_FLAGS and self.no_flags_count > 0:
            self.no_flags_count -= 1

    def _entry_dict(self, entry: Entry, cached: bool = False) -> dict:
        return {
            "chain_id": entry.chain_id,
            "address": entry.address,
            "verdict": entry.verdict,
            "sanctioned": entry.sanctioned,
            "money_laundering": entry.money_laundering,
            "cybercrime": entry.cybercrime,
            "phishing_activities": entry.phishing_activities,
            "stealing_attack": entry.stealing_attack,
            "financial_crime": entry.financial_crime,
            "honeypot_related_address": entry.honeypot_related_address,
            "number_of_malicious_contracts_created": entry.number_of_malicious_contracts_created,
            "mixer": entry.mixer,
            "gas_abuse": entry.gas_abuse,
            "darkweb_transactions": entry.darkweb_transactions,
            "blacklist_doubt": entry.blacklist_doubt,
            "fake_kyc": entry.fake_kyc,
            "fake_standard_interface": entry.fake_standard_interface,
            "fake_token": entry.fake_token,
            "blackmail_activities": entry.blackmail_activities,
            "malicious_mining_activities": entry.malicious_mining_activities,
            "reinit": entry.reinit,
            "triggered_flags": entry.triggered_flags,
            "flag_count": entry.flag_count,
            "data_source": entry.data_source,
            "source_url": entry.source_url,
            "status_code": entry.status_code,
            "fresh": self._is_fresh(entry),
            "cached": cached,
            "checked_seq": entry.checked_seq,
            "disputes": entry.disputes,
            "last_dispute_reason": entry.last_dispute_reason,
            "disputed": entry.disputed,
        }

    def _active_chain(self, chain_id: u64) -> u64:
        chain_id = self._validate_chain_or_raise(chain_id)
        if not self.chains.get(str(chain_id), False):
            raise UserError("Address Reputation Oracle: chain not allowed")
        return chain_id

    def _dispute(self, key: str, reason: str) -> dict:
        entry = self.entries.get(key, None)
        if entry is None:
            raise UserError("Address Reputation Oracle: unknown check")
        entry.disputed = True
        entry.disputes += 1
        entry.last_dispute_reason = reason[:200]
        self.total_disputes += 1
        self.entries[key] = entry
        return self._entry_dict(entry)

    # -- views ---------------------------------------------------------

    @gl.public.view
    def get_verdict(self, chain_id: u64, address: str) -> dict:
        chain_id = self._validate_chain_or_raise(chain_id)
        address = self._normalize_address_or_raise(address)
        entry = self.entries.get(
            self._entry_key(chain_id, address), None
        )
        if entry is None:
            return {
                "chain_id": chain_id,
                "address": address,
                "verdict": VERDICT_UNCHECKED,
                "fresh": False,
                "cached": False,
            }
        return self._entry_dict(entry)

    @gl.public.view
    def get_entry(self, chain_id: u64, address: str) -> dict:
        return self.get_verdict(chain_id, address)

    @gl.public.view
    def is_safe(self, chain_id: u64, address: str) -> bool:
        """True only for a fresh NO_FLAGS_FOUND verdict.

        "Safe" here means exactly "GoPlus reported no known indicators
        for this address at check time". It is NOT proof the address
        is safe — see the module docstring and README.md.
        """
        chain_id = self._validate_chain_or_raise(chain_id)
        address = self._normalize_address_or_raise(address)
        entry = self.entries.get(
            self._entry_key(chain_id, address), None
        )
        if entry is None:
            return False
        return entry.verdict == VERDICT_NO_FLAGS and self._is_fresh(entry)

    @gl.public.view
    def list_entries(self, offset: u64, limit: u64) -> dict:
        total = len(self.entry_order)
        if limit == 0 or limit > MAX_LIST_LIMIT:
            limit = MAX_LIST_LIMIT
        result = []
        if offset < total:
            i = total - offset
            count = 0
            while i > 0 and count < limit:
                i -= 1
                key = self.entry_order[i]
                entry = self.entries.get(key, None)
                if entry is not None:
                    result.append(self._entry_dict(entry))
                    count += 1
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": result,
        }

    @gl.public.view
    def list_chains(self) -> dict:
        result = []
        for chain_id in self.chain_order:
            if self.chains.get(chain_id, False):
                result.append(int(chain_id))
        return {"total": len(result), "chains": result}

    @gl.public.view
    def get_stats(self) -> dict:
        return {
            "total_entries": len(self.entry_order),
            "check_count": self.check_count,
            "flagged": self.flagged_count,
            "caution": self.caution_count,
            "no_flags_found": self.no_flags_count,
            "total_disputes": self.total_disputes,
            "ttl_checks": self.ttl_checks,
            "admin": str(self.admin),
        }

    # -- writes: checking ----------------------------------------------

    @gl.public.write
    def check_address(self, chain_id: u64, address: str) -> dict:
        chain_id = self._active_chain(chain_id)
        address = self._normalize_address_or_raise(address)
        key = self._entry_key(chain_id, address)
        existing = self.entries.get(key, None)
        # Fresh, non-disputed entries are returned without a new
        # consensus round. Disputed entries always re-check.
        if existing is not None and self._is_fresh(existing):
            return self._entry_dict(existing, cached=True)

        # Snapshot consensus inputs BEFORE the nondet block. Storage is
        # never read or written inside leader_fn / validator_fn.
        source_url = render_source_url(chain_id, address)

        def leader_fn():
            response = gl.nondet.web.get(source_url)
            # The real SDK (py-lib-genlayer-std v0.2.16, Response
            # dataclass) exposes the field as `response.status`, and
            # `body` may be None. Same correction SafeLink learned.
            if response.status != 200:
                raise UserError(
                    "Address Reputation Oracle: fetch failed with status "
                    + str(response.status)
                )
            raw_body = response.body or b""
            if isinstance(raw_body, bytes):
                body_text = raw_body.decode("utf-8", "ignore")
            else:
                body_text = str(raw_body)
            signals = derive_signals(
                chain_id,
                address,
                source_url,
                response.status,
                body_text,
            )
            if not signals["parse_ok"]:
                raise UserError(
                    "Address Reputation Oracle: GoPlus data unparseable"
                )
            return signals

        def validator_fn(leaders_res):
            # Leader errors are not agreed on in v1: a failed fetch
            # disagrees and retries with another leader instead of
            # writing anything. See SafeLink's CONSENSUS.md.
            if not isinstance(leaders_res, gl.vm.Return):
                return False
            mine = leader_fn()
            leader = leaders_res.calldata
            for key in COMPARED_SIGNAL_KEYS:
                if mine.get(key) != leader.get(key):
                    return False
            return True

        signals = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        verdict = verdict_from_signals(signals)

        self.check_count += 1
        entry = Entry(
            chain_id=chain_id,
            address=address,
            verdict=verdict,
            sanctioned=signals["sanctioned"],
            money_laundering=signals["money_laundering"],
            cybercrime=signals["cybercrime"],
            phishing_activities=signals["phishing_activities"],
            stealing_attack=signals["stealing_attack"],
            financial_crime=signals["financial_crime"],
            honeypot_related_address=signals["honeypot_related_address"],
            number_of_malicious_contracts_created=signals[
                "number_of_malicious_contracts_created"
            ],
            mixer=signals["mixer"],
            gas_abuse=signals["gas_abuse"],
            darkweb_transactions=signals["darkweb_transactions"],
            blacklist_doubt=signals["blacklist_doubt"],
            fake_kyc=signals["fake_kyc"],
            fake_standard_interface=signals["fake_standard_interface"],
            fake_token=signals["fake_token"],
            blackmail_activities=signals["blackmail_activities"],
            malicious_mining_activities=signals[
                "malicious_mining_activities"
            ],
            reinit=signals["reinit"],
            triggered_flags=signals["triggered_flags"],
            flag_count=signals["flag_count"],
            data_source=signals["data_source"],
            source_url=signals["source_url"],
            status_code=int(signals["status_code"]),
            checked_seq=self.check_count,
            disputes=0 if existing is None else existing.disputes,
            last_dispute_reason=(
                "" if existing is None else existing.last_dispute_reason
            ),
            disputed=False,
        )
        if existing is None:
            self.entry_order.append(key)
        else:
            self._decrement_counter(existing.verdict)
        self._increment_counter(verdict)
        self.entries[key] = entry
        return self._entry_dict(entry)

    # -- writes: disputes -----------------------------------------------

    @gl.public.write
    def dispute_address(
        self, chain_id: u64, address: str, reason: str
    ) -> dict:
        chain_id = self._validate_chain_or_raise(chain_id)
        address = self._normalize_address_or_raise(address)
        return self._dispute(
            self._entry_key(chain_id, address), reason
        )

    @gl.public.write
    def request_recheck(self, chain_id: u64, address: str) -> dict:
        chain_id = self._validate_chain_or_raise(chain_id)
        address = self._normalize_address_or_raise(address)
        return self._dispute(
            self._entry_key(chain_id, address), "recheck requested"
        )

    # -- writes: admin ---------------------------------------------------

    @gl.public.write
    def add_chain(self, chain_id: u64) -> dict:
        self._require_admin()
        if isinstance(chain_id, bool) or not isinstance(chain_id, int):
            raise UserError(
                "Address Reputation Oracle: chain_id must be an int"
            )
        if chain_id <= 0:
            raise UserError("Address Reputation Oracle: chain_id must be > 0")
        if self.chains.get(str(chain_id), False):
            raise UserError("Address Reputation Oracle: chain already allowed")
        self.chains[str(chain_id)] = True
        self.chain_order.append(str(chain_id))
        return self.list_chains()

    @gl.public.write
    def remove_chain(self, chain_id: u64) -> dict:
        self._require_admin()
        if isinstance(chain_id, bool) or not isinstance(chain_id, int):
            raise UserError(
                "Address Reputation Oracle: chain_id must be an int"
            )
        if not self.chains.get(str(chain_id), False):
            raise UserError("Address Reputation Oracle: chain not allowed")
        # Tombstone, not a physical remove: DynArray has no verified
        # remove/clear/pop.
        self.chains[str(chain_id)] = False
        return self.list_chains()

    @gl.public.write
    def set_ttl_checks(self, ttl: u64) -> dict:
        self._require_admin()
        if ttl == 0:
            raise UserError("Address Reputation Oracle: ttl must be > 0")
        self.ttl_checks = ttl
        return {"ttl_checks": self.ttl_checks}
