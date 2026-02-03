# CMR Reference (Rust)

This project implements the CMR protocol defined in `agi2.html` (Appendix A) as a Rust workspace:

- `crates/cmr-core`: strict protocol parser/encoder, router logic, policy, key exchange.
- `crates/cmr-peer`: network peer daemon (HTTP, HTTPS, UDP listeners; HTTP/HTTPS/SMTP/UDP/SSH outbound).
- `crates/cmr-compressor`: isolated compressor worker that uses `infotheory` `1.0.0` from GitHub.

## Security-Critical Design

- Compressors are separated into a dedicated worker process (`cmr-compressor`).
- Router process only holds protocol/network logic and talks to worker over bounded IPC.
- Default policy is strict (`SecurityLevel::Strict`) with:
  - CRLF-strict parsing and timestamp ordering checks.
  - pairwise signature verification (`SHA-256(key || header+body)`).
  - flood/rate controls (peer and global windows).
  - intrinsic-dependence spam filtering (via `infotheory`).
  - executable payload blocking and reputation-based admission.

## Implemented CMR Pieces

- Message format (signature/header/body) and strict validation.
- Router behavior: accept/reject, cache, matching, forwarding, per-hop re-signing.
- Transports:
  - Server: HTTP, HTTPS, UDP.
  - Client: HTTP, HTTPS, SMTP, UDP, SSH.
  - HTTP handshake (`request`/`reply`) including one-time payload store.
- Key exchange control messages:
  - RSA request/reply.
  - Diffie-Hellman request/reply.
  - Clear key exchange (only accepted over secure transport).

## Build

```bash
cargo build --workspace --release
```

## Test

```bash
cargo test --workspace
```

Test coverage now includes:

- `crates/cmr-core/tests/core_tests.rs`:
  - protocol parsing/validation edge cases,
  - signature modes and verification,
  - key-exchange parsing and control flows,
  - router security policy decisions (spam, flood, reputation/signature gates),
  - forwarding behavior and re-signing guarantees.
- `crates/cmr-compressor/tests/worker_ipc.rs`:
  - compressor worker process IPC end-to-end and metric responses.
- `crates/cmr-peer/tests/config_transport.rs`:
  - config parsing,
  - multipart/plain payload extraction,
  - handshake store semantics,
  - UDP transport send/receive,
  - HTTP forwarding end-to-end (router -> transport -> HTTP receiver).

## Run Peer

1. Copy `cmr-peer.example.toml` to `cmr-peer.toml` and edit values.
2. Start peer:

```bash
cargo run -p cmr-peer -- run --config cmr-peer.toml
```

3. Optional SSH forced-command mode (ingest one message from stdin):

```bash
cargo run -p cmr-peer -- receive-stdin --config cmr-peer.toml --transport ssh
```

## Notes

- SMTP inbound is typically handled by your MTA and piped to `receive-stdin`.
- For HTTPS listener, provide PEM cert/key paths in config.
- Use pairwise unique shared keys per peer.
