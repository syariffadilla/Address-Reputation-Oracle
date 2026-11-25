"""Test harness: a minimal fake ``genlayer`` module.

Adapted from the Token Safety Oracle's tests/conftest.py (same stub
semantics), GET-only — the Address Reputation Oracle fetches GoPlus
with GET and nothing else. The real GenLayer SDK / GenVM runner is NOT
installed here, so the contract is loaded with this stub. The stub
emulates the documented semantics just enough to exercise the contract
end to end off-chain:

* ``@gl.public.view`` / ``@gl.public.write`` are identity decorators.
* ``gl.message.sender_address`` is a settable attribute (the caller).
* ``gl.nondet.web.get(url)`` serves canned responses from
  ``WEB_RESPONSES`` and records every call in ``WEB_CALLS``.
* ``gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`` calls the leader,
  wraps the result in ``gl.vm.Return``, calls the validator, and returns
  the leader's value only if the validator agrees. Disagreement (or a
  leader error the validator does not agree with) raises RuntimeError —
  the stub's emulation of "transaction undetermined, no state change".
* ``TreeMap`` / ``DynArray`` are dict / list subclasses; ``u64`` etc.
  are plain ``int``; ``Address`` is ``str``.

These are DIRECT-mode tests: they prove the contract's logic, state
machine and validator agreement — they do NOT prove the contract passes
GenVM lint or Studio consensus. That step is still open; see README.md.
"""

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = ROOT / "contracts"
sys.path.insert(0, str(CONTRACTS_DIR))

import address_reputation_logic  # noqa: E402  (pure logic, no GenLayer import)

# ---------------------------------------------------------------- fake gl

WEB_RESPONSES = {}
WEB_CALLS = []


class _FakeResponse:
    def __init__(self, status, body):
        # Mirrors the real SDK Response dataclass: fields are `status`
        # (not `status_code`) and `body` (bytes).
        self.status = status
        self.body = body.encode("utf-8") if isinstance(body, str) else body


def _serve(store, calls, key):
    calls.append(key)
    if key not in store:
        return _FakeResponse(404, "not found")
    value = store[key]
    if isinstance(value, list):
        # Consumed in order: lets tests change the source between the
        # leader's fetch and the validator's re-fetch.
        status_code, body = value.pop(0)
    else:
        status_code, body = value
    return _FakeResponse(status_code, body)


class _FakeWeb:
    @staticmethod
    def get(url):
        return _serve(WEB_RESPONSES, WEB_CALLS, url)


class _UserError(Exception):
    pass


class _VMError(Exception):
    pass


class _Return:
    def __init__(self, calldata):
        self.calldata = calldata


class _LeaderError:
    """Non-Return result: the leader raised instead of returning."""

    def __init__(self, error):
        self.error = error


def _run_nondet_unsafe(leader_fn, validator_fn):
    try:
        value = leader_fn()
    except Exception as exc:  # leader raised (e.g. gl.UserError on 404)
        agreed = validator_fn(_LeaderError(exc))
        if agreed:
            raise exc
        raise RuntimeError("consensus failed: leader error not agreed")
    if validator_fn(_Return(value)):
        return value
    raise RuntimeError("consensus failed: validator disagreed")


def _make_fake_genlayer():
    fake = types.ModuleType("genlayer")

    class _TreeMap(dict):
        def __class_getitem__(cls, item):
            return cls

    class _DynArray(list):
        def __class_getitem__(cls, item):
            return cls

    def _storage_default(annotation):
        if annotation is _TreeMap:
            return {}
        if annotation is _DynArray:
            return []
        if annotation is int:
            return 0
        if annotation is bool:
            return False
        if annotation is str:
            return ""
        return None

    class _ContractBase:
        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            orig_init = cls.__init__

            def wrapped_init(self, *args, **kwargs):
                for name, ann in cls.__annotations__.items():
                    setattr(self, name, _storage_default(ann))
                orig_init(self, *args, **kwargs)

            cls.__init__ = wrapped_init

    class _Public:
        @staticmethod
        def view(fn):
            return fn

        @staticmethod
        def write(fn):
            return fn

    class _Message:
        sender_address = "0x00000000000000000000000000000000000000A1"

    fake.public = _Public()
    fake.message = _Message()
    fake.UserError = _UserError
    fake.VMError = _VMError
    fake.allow_storage = lambda cls: cls
    fake.Contract = _ContractBase
    fake.Address = str
    fake.TreeMap = _TreeMap
    fake.DynArray = _DynArray
    fake.u64 = int
    fake.u256 = int
    fake.u32 = int
    fake.i32 = int
    fake.i64 = int
    fake.vm = types.SimpleNamespace(
        Return=_Return,
        Result=_Return,
        UserError=_UserError,
        VMError=_VMError,
        run_nondet_unsafe=_run_nondet_unsafe,
    )
    fake.nondet = types.SimpleNamespace(web=_FakeWeb())
    fake.gl = fake
    fake.__all__ = [
        "gl",
        "allow_storage",
        "Contract",
        "public",
        "message",
        "UserError",
        "VMError",
        "Address",
        "TreeMap",
        "DynArray",
        "u64",
        "u256",
        "u32",
        "i32",
        "i64",
        "vm",
        "nondet",
    ]
    return fake


def load_contract():
    """Load contracts/address_reputation_oracle.py with the fake genlayer module."""
    fake = _make_fake_genlayer()
    # The contract imports UserError from the REAL SDK location
    # (genlayer.gl.vm) — the fake must expose that submodule path too.
    # NOTE (15 Nov 2026, found on the Oracle): real SDK v0.2.5/v0.2.16
    # has NO gl.UserError; it lives in genlayer.gl.vm. The fake
    # mirrors that, and the contract imports it from there.
    gl_mod = types.ModuleType("genlayer.gl")
    vm_mod = types.ModuleType("genlayer.gl.vm")
    vm_mod.UserError = _UserError
    vm_mod.VMError = _VMError
    vm_mod.Return = _Return
    vm_mod.run_nondet_unsafe = _run_nondet_unsafe
    gl_mod.vm = vm_mod
    fake.__path__ = []  # make the fake importable as a package
    sys.modules["genlayer"] = fake
    sys.modules["genlayer.gl"] = gl_mod
    sys.modules["genlayer.gl.vm"] = vm_mod
    spec = importlib.util.spec_from_file_location(
        "address_reputation_contract",
        CONTRACTS_DIR / "address_reputation_oracle.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, fake


def reset_web():
    WEB_RESPONSES.clear()
    WEB_CALLS.clear()


def set_sender(fake, address):
    fake.message.sender_address = address


ADMIN = "0x00000000000000000000000000000000000000A1"
OTHER = "0x00000000000000000000000000000000000000B2"

# Live-verified demo data (25 Nov 2026, GoPlus address_security fetched
# live by curl; full bodies saved at tests-direct/fixtures/).
# Creator of the fake-USDC honeypot from the Token Safety demos.
FLAGGED_CREATOR = "0xe8e0960da069c336852246a5bedf18ad05ea25e7"
FLAGGED_CREATOR_CHAIN = 56
VITALIK = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
VITALIK_CHAIN = 1
VITALIK_BSC_CHAIN = 56
# Ronin bridge exploiter — CORRECTED 25 Nov 2026: the address in
# DESIGN.md v1 had a typo (41 hex chars, trailing "d"). The real
# address is 0x098b716b8aaf21512996dc57eb0615e2383e2f96 (Etherscan:
# "Ronin Bridge Exploiter"). GoPlus DOES flag it: sanctioned=1,
# stealing_attack=1, blacklist_doubt=1, data_source SlowMist,BlockSec.
# The DESIGN.md claim "Ronin returns all zeros" was wrong — it was
# measured against the typo'd address, which GoPlus answers with
# all zeros without validating length.
RONIN = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"
RONIN_CHAIN = 1
DEAD = "0x0000000000000000000000000000000000000001"
GOPLUS_URL = (
    "https://api.gopluslabs.io/api/v1/address_security"
    "/{address}?chain_id={chain}"
)


def goplus_url(chain, address):
    return GOPLUS_URL.format(chain=chain, address=address)


ALL_FLAGS = (
    "sanctioned",
    "money_laundering",
    "cybercrime",
    "phishing_activities",
    "stealing_attack",
    "financial_crime",
    "honeypot_related_address",
    "number_of_malicious_contracts_created",
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


def _full_flags(**overrides):
    flags = {key: "0" for key in ALL_FLAGS}
    flags.update(overrides)
    return flags


def _goplus_body(flags, data_source=""):
    result = dict(flags)
    result["data_source"] = data_source
    return json.dumps({"code": 1, "message": "ok", "result": result})


def flagged_json():
    """Fake-USDC creator on BSC — honeypot_related_address=1 and one
    malicious contract created. FLAGGED. Live-verified 25 Nov 2026."""
    return _goplus_body(
        _full_flags(
            honeypot_related_address="1",
            number_of_malicious_contracts_created="1",
        ),
        data_source="GoPlus",
    )


def vitalik_json():
    """Vitalik on Ethereum — every flag "0". NO_FLAGS_FOUND.
    Live-verified 25 Nov 2026 (also on BSC 56, same all-zeros)."""
    return _goplus_body(_full_flags())


def ronin_json():
    """Ronin exploiter on Ethereum — sanctioned=1, stealing_attack=1,
    blacklist_doubt=1, data_source SlowMist,BlockSec. FLAGGED.
    Live-verified 25 Nov 2026 with the CORRECTED address (see the
    RONIN comment above). The DESIGN.md all-zeros claim was measured
    against a typo'd 41-char address and is wrong."""
    return _goplus_body(
        _full_flags(
            sanctioned="1",
            stealing_attack="1",
            blacklist_doubt="1",
        ),
        data_source="SlowMist,BlockSec",
    )


def caution_json():
    """SYNTHETIC — no live CAUTION demo address was found (four
    plausible candidates all returned all zeros, 25 Nov 2026).
    One contextual flag only (mixer=1), everything else "0".
    CAUTION. The branch is covered by stub + direct tests until a
    real CAUTION address is found."""
    return _goplus_body(_full_flags(mixer="1"))


def count_only_json():
    """Only the malicious-contracts count is positive ("3"), no binary
    flag is "1". FLAGGED via the count rule. Synthetic."""
    return _goplus_body(
        _full_flags(number_of_malicious_contracts_created="3")
    )


def missing_flag_json():
    """Result missing the "mixer" key entirely — parse_ok False,
    no verdict. Synthetic."""
    flags = _full_flags()
    del flags["mixer"]
    return _goplus_body(flags)


def malformed_flag_json():
    """A binary flag with an unexpected value ("2") — parse_ok False,
    no verdict. Synthetic."""
    return _goplus_body(_full_flags(mixer="2"))


def bad_count_json():
    """The count field with a non-numeric value — parse_ok False,
    no verdict. Synthetic."""
    return _goplus_body(
        _full_flags(number_of_malicious_contracts_created="many")
    )


def empty_result_json():
    """GoPlus code 1 with an empty result map."""
    return json.dumps({"code": 1, "message": "ok", "result": {}})


def system_error_json():
    """GoPlus code 5000, result null."""
    return json.dumps({"code": 5000, "message": "system error", "result": None})
