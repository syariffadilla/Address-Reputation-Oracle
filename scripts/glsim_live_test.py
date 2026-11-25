"""Live GenVM test on glsim: deploy the Address Reputation Oracle to a
local 5-validator GenLayer network and run real consensus checks
against the LIVE GoPlus API (no mocks anywhere).

Run with SafeLink's venv, while glsim is up on :4000 (FRESH server —
one deploy per glsim server process, see Oracle TEST_LOG 15 Nov):
    ../../genlayer-intelligent-contracts-submission/safelink/.venv/bin/glsim --port 4000 --no-browser
    ../../genlayer-intelligent-contracts-submission/safelink/.venv/bin/python scripts/glsim_live_test.py

Writes results to scripts/glsim_live_result.json (timings included).
Each consensus round makes the leader AND every validator fetch the
GoPlus record independently.

Note: GoPlus address_security answers code 1 with a full flag set for
essentially every query (even dead addresses and unsupported chains),
so there is no live UNCHECKED demo — the no-verdict branches are
covered by the stub suite and the GenVM direct tests (404 mock,
system-error body, missing/malformed flag). The live run proves the
three verdict branches plus the honest-limit case.
"""

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(
    0,
    str(ROOT.parent.parent / "genlayer-intelligent-contracts-submission" / "safelink" / ".venv" / "lib" / "python3.12" / "site-packages"),
)

from genlayer_py import create_account, create_client
from genlayer_py.chains import localnet
from genlayer_py.types import TransactionStatus
from gltest.utils import extract_contract_address

CONTRACT_PATH = ROOT / "contracts" / "address_reputation_oracle.py"

# Pinned demo addresses (all live-verified by curl 25 Nov 2026;
# fixtures in tests-direct/fixtures/).
FLAGGED_CREATOR_BSC = "0xe8e0960da069c336852246a5bedf18ad05ea25e7"  # FLAGGED
VITALIK_ETH = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"        # NO_FLAGS_FOUND
VITALIK_BSC = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"        # NO_FLAGS_FOUND
RONIN_ETH = "0x098b716b8aaf21512996dc57eb0615e2383e2f96"          # FLAGGED (sanctioned + stealing_attack)

RESULTS = {"checks": []}


def record(name, ok, detail, seconds=None):
    RESULTS["checks"].append(
        {"name": name, "ok": bool(ok), "detail": detail, "seconds": seconds}
    )
    print(f"[{'PASS' if ok else 'FAIL'}] {name} ({seconds}s)" if seconds is not None else f"[{'PASS' if ok else 'FAIL'}] {name}")
    print(f"    {detail}")


def wait(client, tx_hash, label):
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hash,
        status=TransactionStatus.ACCEPTED,
        interval=2,
        retries=120,
        full_transaction=True,
    )
    print(f"    {label} receipt status: {receipt.get('status')} ({receipt.get('status_name')})")
    return receipt


def extract_address(receipt):
    for path in (
        ("tx_data_decoded", "contract_address"),
        ("data", "contract_address"),
    ):
        node = receipt.get(path[0]) or {}
        if isinstance(node, dict) and node.get(path[1]):
            return node[path[1]]
    if receipt.get("contract_address"):
        return receipt["contract_address"]
    return None


def main():
    admin = create_account()
    print(f"admin: {admin.address}")
    client = create_client(chain=localnet, account=admin)
    try:
        client.fund_account(admin.address, 10**21)
    except Exception as exc:
        # genlayer-py 0.16.3 mis-parses the sim_fundAccount reply
        # (expects a tx hash, gets {"balance": ...}) — the funding
        # itself lands server-side; continue.
        print(f"fund_account parse quirk (ignored): {exc}")
    print("funded admin")

    code = CONTRACT_PATH.read_text()
    t0 = time.time()
    tx_hash = client.deploy_contract(code=code, account=admin)
    receipt = wait(client, tx_hash, "deploy")
    address = extract_address(receipt)
    if not address:
        raise SystemExit(f"deploy receipt has no contract address: {json.dumps(receipt, default=str)[:1500]}")
    RESULTS["contract_address"] = address
    print(f"deployed at {address} in {time.time() - t0:.1f}s")

    def write(fn, *args):
        t0 = time.time()
        tx = client.write_contract(
            address=address, function_name=fn, account=admin, args=list(args)
        )
        wait(client, tx, fn)
        return time.time() - t0

    def read(fn, *args):
        return client.read_contract(
            address=address, function_name=fn, account=admin, args=list(args)
        )

    # --- deploy defaults ---
    stats = read("get_stats")
    record(
        "deploy_defaults",
        stats.get("check_count") == 0 and stats.get("total_entries") == 0,
        f"stats={stats}",
    )

    # --- fake-USDC creator BSC live: FLAGGED ---
    dt = write("check_address", 56, FLAGGED_CREATOR_BSC)
    got = read("get_verdict", 56, FLAGGED_CREATOR_BSC)
    record(
        "flagged_creator_live_flagged",
        got.get("verdict") == "flagged",
        f"verdict={got.get('verdict')} triggered={got.get('triggered_flags')} count={got.get('flag_count')}",
        round(dt, 1),
    )

    # --- Vitalik Eth live: NO_FLAGS_FOUND ---
    dt = write("check_address", 1, VITALIK_ETH)
    got = read("get_verdict", 1, VITALIK_ETH)
    record(
        "vitalik_eth_live_no_flags",
        got.get("verdict") == "no_flags_found",
        f"verdict={got.get('verdict')} flag_count={got.get('flag_count')}",
        round(dt, 1),
    )

    # --- Vitalik BSC live: NO_FLAGS_FOUND ---
    dt = write("check_address", 56, VITALIK_BSC)
    got = read("get_verdict", 56, VITALIK_BSC)
    record(
        "vitalik_bsc_live_no_flags",
        got.get("verdict") == "no_flags_found",
        f"verdict={got.get('verdict')} flag_count={got.get('flag_count')}",
        round(dt, 1),
    )

    # --- Ronin exploiter Eth live: FLAGGED (sanctioned + stealing_attack) ---
    dt = write("check_address", 1, RONIN_ETH)
    got = read("get_verdict", 1, RONIN_ETH)
    record(
        "ronin_live_flagged",
        got.get("verdict") == "flagged",
        f"verdict={got.get('verdict')} triggered={got.get('triggered_flags')} count={got.get('flag_count')}",
        round(dt, 1),
    )

    stats = read("get_stats")
    RESULTS["stats"] = stats
    print(f"stats: {stats}")

    out = ROOT / "scripts" / "glsim_live_result.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(RESULTS, indent=2))
    print(f"results -> {out}")
    failed = [c for c in RESULTS["checks"] if not c["ok"]]
    print(f"{len(RESULTS['checks']) - len(failed)}/{len(RESULTS['checks'])} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
