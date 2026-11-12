#!/bin/sh
set -eu

if [ ! -r /run/secrets/swarm-key ]; then
    echo "Missing required IPFS private-network key." >&2
    exit 1
fi

if [ ! -f /data/ipfs/config ]; then
    gosu ipfs ipfs init --profile server
    gosu ipfs ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
    gosu ipfs ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
fi

gosu ipfs install -m 0400 /run/secrets/swarm-key /data/ipfs/swarm.key
gosu ipfs ipfs config --json Bootstrap '[]'
gosu ipfs ipfs config --json Swarm.DisableNatPortMap true
gosu ipfs ipfs config --json Swarm.AddrFilters '[]'
# This private swarm must not depend on public bootstrap or delegated-routing
# services. Kubo 0.43.1's default "auto" mode falls back to WAN-only DHT when
# AutoConf is disabled, so configure its LAN DHT explicitly.
gosu ipfs ipfs config --json DNS.Resolvers '{}'
gosu ipfs ipfs config --json Routing.DelegatedRouters '[]'
gosu ipfs ipfs config --json Ipns.DelegatedPublishers '[]'
gosu ipfs ipfs config --json Routing.Type '"custom"'
gosu ipfs ipfs config Routing.Routers.LanDHT --json \
    '{"Type":"dht","Parameters":{"Mode":"server","PublicIPNetwork":false,"AcceleratedDHTClient":false}}'
gosu ipfs ipfs config Routing.Methods --json \
    '{"find-peers":{"RouterName":"LanDHT"},"find-providers":{"RouterName":"LanDHT"},"get-ipns":{"RouterName":"LanDHT"},"provide":{"RouterName":"LanDHT"},"put-ipns":{"RouterName":"LanDHT"}}'
# Kubo 0.43.1's sweep provider is a no-op for custom routing with a DHT
# router; use the legacy provider so configured LAN DHT methods are honored.
gosu ipfs ipfs config --bool Provide.DHT.SweepEnabled false
gosu ipfs ipfs config --bool AutoConf.Enabled false
gosu ipfs ipfs config --bool AutoTLS.Enabled false

if [ -n "${KUBO_BOOTSTRAP_FROM:-}" ]; then
    bootstrap_api="/dns4/$KUBO_BOOTSTRAP_FROM/tcp/5001"
    bootstrap_peer_id=""
    attempt=0
    while [ "$attempt" -lt 30 ] && [ -z "$bootstrap_peer_id" ]; do
        bootstrap_peer_id=$(
            ipfs --api "$bootstrap_api" id -f='<id>' 2>/dev/null || true
        )
        attempt=$((attempt + 1))
        if [ -z "$bootstrap_peer_id" ]; then
            sleep 2
        fi
    done
    if [ -z "$bootstrap_peer_id" ]; then
        echo "Unable to retrieve the private Kubo bootstrap peer identity." >&2
        exit 1
    fi
    bootstrap_address="/dns4/$KUBO_BOOTSTRAP_FROM/tcp/4001/p2p/$bootstrap_peer_id"
    gosu ipfs ipfs config --json Bootstrap "[\"$bootstrap_address\"]"
fi

exec /usr/local/bin/start_ipfs "$@"
