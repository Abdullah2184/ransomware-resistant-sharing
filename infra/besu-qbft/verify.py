#!/usr/bin/env python3
"""Verify the host-published Besu RPC node and QBFT-committed head."""

import json
import os
import time
import urllib.error
import urllib.request


def local_config(name: str, default: str) -> str:
    if name in os.environ:
        return os.environ[name]
    root_env = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
    try:
        with open(root_env, encoding="utf-8") as config:
            for line in config:
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip().strip("\"'")
    except OSError:
        pass
    return default


RPC_URL = local_config("BESU_RPC_URL", "http://127.0.0.1:8545")
EXPECTED_CHAIN_ID = int(local_config("BESU_CHAIN_ID", "1337"), 0)


def call(method: str, params: list) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        RPC_URL,
        body,
        {"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(f"{method} returned a JSON-RPC error")
    return result["result"]


deadline = time.monotonic() + 120
last_error: Exception | None = None
while time.monotonic() < deadline:
    try:
        chain_id = int(call("eth_chainId", []), 16)
        peers = int(call("net_peerCount", []), 16)
        committed = call("eth_getBlockByNumber", ["latest", False])
        validators = call("qbft_getValidatorsByBlockNumber", ["latest"])
        if chain_id != EXPECTED_CHAIN_ID:
            raise RuntimeError(f"RPC chain ID {chain_id} differs from expected {EXPECTED_CHAIN_ID}")
        if committed is None or not committed.get("hash"):
            raise RuntimeError("RPC did not return the QBFT-committed head")
        if len(validators) != 4:
            raise RuntimeError(f"expected four QBFT validators, got {len(validators)}")
        if peers < 3:
            raise RuntimeError(f"RPC node has only {peers} connected validator peers")
        print(f"chainId={chain_id}")
        print(f"rpcPeerCount={peers}")
        print(f"qbftCommittedBlock={int(committed['number'], 16)}")
        print(f"validatorCount={len(validators)}")
        break
    except (OSError, ValueError, KeyError, RuntimeError, urllib.error.URLError) as error:
        last_error = error
        time.sleep(2)
else:
    raise SystemExit(f"Besu QBFT verification failed: {last_error}")
