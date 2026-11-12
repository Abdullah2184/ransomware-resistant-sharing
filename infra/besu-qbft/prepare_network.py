#!/usr/bin/env python3
"""Map Besu-generated local validator keys to stable Compose service names."""

import re
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    image = sys.argv[1]
    source = root / "networkFiles"
    generated = root / "generated"
    if generated.exists():
        raise SystemExit("generated/ already exists; inspect it before proceeding")

    validator_dirs = sorted(
        path for path in (source / "keys").iterdir() if path.is_dir()
    )
    if len(validator_dirs) != 4:
        raise SystemExit("Besu did not generate exactly four validator key directories")
    if not (source / "genesis.json").is_file():
        raise SystemExit("Besu did not generate genesis.json")

    (generated / "validators").mkdir(parents=True)
    shutil.copy2(source / "genesis.json", generated / "genesis.json")
    node_ids = []
    uid_gid = f"{__import__('os').getuid()}:{__import__('os').getgid()}"
    for index, source_dir in enumerate(validator_dirs, start=1):
        target = generated / "validators" / f"validator{index}"
        target.mkdir()
        for name in ("key", "key.pub"):
            source_key = source_dir / name
            if not source_key.is_file():
                raise SystemExit(f"missing generated validator key file: {source_key.name}")
            shutil.copy2(source_key, target / name)
        (target / "key").chmod(0o600)

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                uid_gid,
                "-v",
                f"{root}:/work",
                "-w",
                "/work",
                image,
                "public-key",
                "export",
                f"--node-private-key-file=/work/generated/validators/validator{index}/key",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        candidates = re.findall(r"(?:0x)?([0-9a-fA-F]{128})", result.stdout)
        if not candidates:
            raise SystemExit("Besu could not export a generated validator public key")
        node_ids.append(candidates[-1].lower())

    bootnodes = "\n".join(
        f"enode://{node_id}@validator{index}:30303"
        for index, node_id in enumerate(node_ids, start=1)
    )
    (generated / "bootnodes.txt").write_text(bootnodes + "\n", encoding="ascii")
    (generated / "bootnodes.txt").chmod(0o644)
    print("Generated four validator key directories and the QBFT genesis file under infra/besu-qbft/generated/.")
    print("Validator private keys are local development credentials; keep the generated directory private.")


if __name__ == "__main__":
    main()
