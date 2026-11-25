"""Pure, deterministic Address Reputation Oracle logic.

Stdlib only — no GenLayer imports — so this module is unit-testable with
plain pytest and no GenVM. The contract file
``contracts/address_reputation_oracle.py`` contains byte-identical
copies of these functions (checked by ``tests/test_contract_sync.py``);
the contract is self-contained because a single-file GenLayer contract
cannot import a sibling module on-chain.

Design (see DESIGN.md for the full story):

* The verdict is a DETERMINISTIC rule over GoPlus address-security
  flags (see verdict_from_signals). No LLM is called anywhere in v1.
  Validators re-fetch the same GoPlus URL and compare the derived
  signals exactly.
* Only the signal fields listed in ``COMPARED_SIGNAL_KEYS`` are part of
  consensus. ``content_len`` / ``body_sample`` / ``data_source`` are
  audit observations; they are recorded, never compared.
* A verdict is written ONLY on exact agreement. A fetch failure, a
  non-200 status, a non-OK GoPlus code, an empty result, an unparseable
  body, a missing or malformed flag, or validator disagreement writes
  nothing — the same safe-failure as SafeLink and the Token Safety
  Oracle.
* Flags arrive as strings. The 17 binary flags must be exactly ``"0"``
  or ``"1"``; ``number_of_malicious_contracts_created`` is a COUNT
  string and must parse as a non-negative integer. Anything else is
  treated as missing data: no verdict. This is the strict reading of
  DESIGN.md ("Missing or null indicators are UNKNOWN (no verdict),
  not zero") extended to malformed values — a safety oracle fails
  closed, never by guessing.
* ``contract_address`` and ``data_source`` are EXCLUDED from the
  compared fields, per DESIGN.md: ``contract_address`` is unreliable
  (an EOA, Vitalik included, returns ``"1"`` for it), and
  ``data_source`` varies per address (``"GoPlus"`` for flagged
  addresses, ``""`` for clean ones) and adds no verdict signal.
"""

import json

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
