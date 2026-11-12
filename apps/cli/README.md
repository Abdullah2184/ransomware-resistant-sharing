# Command-line client (Phase 5)

The CLI currently provides a gateway health check:

```shell
cargo run -p cli -- health
cargo run -p cli -- health http://127.0.0.1:8080
```

`GATEWAY_URL` sets the gateway base URL; the default is
`http://127.0.0.1:8080`. The command requests `/healthz`, returns a nonzero exit
status on invalid configuration, connection failure, or an unhealthy HTTP
response, and does not send credentials. The base URL must not contain
userinfo, query parameters, or a fragment. Each health request has a five
second timeout.

The Phase 5 identity, listing, upload, download, modify, history, sharing,
revocation, and recovery workflows are not implemented yet. The current
gateway does not expose most of those operations, and `application` has no
use-case services. New commands must call application services and supported
gateway routes; they must not implement authorization in the CLI or assume an
endpoint that does not exist.
