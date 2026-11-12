#!/bin/sh
set -eu

module_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
image=${BESU_IMAGE:-hyperledger/besu:26.11.0@sha256:3d6ac0368d449c13c4ba075acac90d6b96afa5b3113295385d88c4d5122c8808}

if [ -e "$module_dir/generated" ] || [ -e "$module_dir/networkFiles" ]; then
    echo "Local generated Besu files already exist. Inspect them; this script will not overwrite them." >&2
    exit 1
fi

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$module_dir:/work" \
    -w /work \
    "$image" \
    operator generate-blockchain-config \
    --config-file=/work/qbft-config.json \
    --to=/work/networkFiles \
    --private-key-file-name=key

python3 "$module_dir/prepare_network.py" "$image"
