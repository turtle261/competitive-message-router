# Competitive Message Routing (CMR)
[![Rust CI](https://github.com/turtle261/competitive-message-router/actions/workflows/rust.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/rust.yml)
[![Security](https://github.com/turtle261/competitive-message-router/actions/workflows/security.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/security.yml)
[![CodeQL](https://github.com/turtle261/competitive-message-router/actions/workflows/codeql.yml/badge.svg)](https://github.com/turtle261/competitive-message-router/actions/workflows/codeql.yml)

This project implements the CMR protocol defined in `agi2.html` as a Rust workspace, including the Appendix A wire format and the Section 3.2 routing strategy.

- `crates/cmr-core`: strict protocol parser/encoder, router logic, policy, key exchange.
- `crates/cmr-peer`: network peer daemon (HTTP, HTTPS, UDP listeners; HTTP/HTTPS/SMTP/UDP/SSH outbound).
- `crates/cmr-compressor`: isolated compressor worker that uses [infotheory](https://github.com/turtle261/infotheory) for CMR compression-distance metrics and intrinsic-dependence spam mitigations.

## Security-Critical Design

- Compressors are separated into a dedicated worker process (`cmr-compressor`).
- Router process only holds protocol/network logic and talks to worker over bounded IPC.
- Default policy is strict (`SecurityLevel::Strict`) with:
  - CRLF-strict parsing and timestamp ordering checks.
  - pairwise signature verification (`HMAC-SHA256(header+body, key)`) with constant-time digest compare.
  - sliding-window flood/rate controls (peer and global windows).
  - intrinsic-dependence spam filtering (via `infotheory`).
  - executable payload blocking and reputation-based admission.
  - bounded HTTP-handshake payload storage (entry/size caps + TTL).
  - strict callback validation for HTTP-handshake reply fetches (requester host/IP must resolve to and match remote peer IP).
  - SSH destination path is command-sanitized (single safe token only) to prevent command injection.

## Implemented CMR Pieces

- Message format (signature/header/body) and strict validation.
- Router behavior: accept/reject, cache, exact Section 3.2 compression-difference routing (`D(X, Y) = C(XY)-C(X)+C(YX)-C(Y)`), raw-distance threshold-based forwarding across individually matched messages (A3/3.3), compensatory `Z_j` replies, bounded cache eviction when limits are reached, and per-hop re-signing.
- Transports:
  - Server: HTTP, HTTPS, UDP, SMTP.
  - Client: HTTP, HTTPS, SMTP, UDP, SSH.
  - HTTP handshake (`request`/`reply`) including one-time payload store.
  - UDP service-tag framing (`udp://host:port/service`) enforced on send/receive.
  - SMTP payloads are sent as `application/octet-stream` with base64 transfer encoding.
- Key exchange control messages:
  - Automatic first-contact key-exchange planning for unknown peers (RSA or DH, policy-selectable). The router emits `ClientMessagePlan`; the peer daemon client layer creates/sends the wire message.
  - RSA request/reply.
  - Diffie-Hellman request/reply.
  - Clear key exchange (only accepted over secure transport).
  - RSA/DH shared secrets are normalized with HKDF-SHA256 before use as pairwise keys.

## Install (crates.io)

Install the peer daemon and compressor worker:

```bash
cargo install cmr-peer cmr-compressor
```

If `cmr-peer` is not found after install, add Cargo's bin directory to `PATH`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

## Quick Start

1. Generate a config template:

```bash
cmr-peer init-config --config cmr-peer.toml
```

2. Edit `cmr-peer.toml`:
- set `local_address` to this peer's externally reachable address.
- set listener bind/path values in `[listen.http]`/`[listen.https]`/`[listen.udp]` (and optional `[listen.smtp]` for inbound `mailto:`).
- keep `[compressor].command = "cmr-compressor"` unless you need a custom path.
- dashboard defaults to disabled; if you enable it, you must set both `dashboard.auth_username` and `dashboard.auth_password`.
- public web-client UI defaults to disabled; enable `[web_client]` to expose a client-only compose UI/API separate from operator dashboard auth.

3. Run the peer:

```bash
cmr-peer run --config cmr-peer.toml
```

4. Optional local smoke test:

```bash
cmr-peer self-test --config cmr-peer.toml --spawn-runtime
```

5. Optional SSH forced-command mode (ingest one message from stdin):

```bash
cmr-peer receive-stdin --config cmr-peer.toml --transport ssh
```

## Basic Client Usage

This is the simplest end-user path using installed binaries.

1. Install from crates.io (see `Install (crates.io)` above), then create config:

```bash
cmr-peer init-config --config cmr-peer.toml
```

Minimum useful local settings in `cmr-peer.toml`:

```toml
local_address = "http://127.0.0.1:4001/"

[listen.http]
bind = "127.0.0.1:4001"
path = "/"
```

2. (Optional) enable operator dashboard UI:

```toml
[dashboard]
enabled = true
path = "/_cmr"
auth_username = "operator"
auth_password = "change-me"
```

Dashboard transport/auth rules:
- Non-localhost dashboard access requires HTTPS.
- HTTP dashboard access is allowed only from loopback/local addresses.
- Dashboard requests are rejected unless both basic-auth fields are configured.

3. (Optional) enable public web client UI (no auth):

```toml
[web_client]
enabled = true
path = "/_cmr_client"
require_https = true
```

Web client transport rules:
- `require_https = true` allows HTTP only from loopback/local addresses and requires HTTPS for non-localhost access.
- The web client only exposes client compose endpoints and cannot access operator runtime/config controls.

4. Start peer:

```bash
cmr-peer run --config cmr-peer.toml
```

5. Post and view messages:
- Open `http://127.0.0.1:4001/_cmr` and use `Post To Message Pool`.
- Open `http://127.0.0.1:4001/_cmr_client` for client-only compose with optional per-message identity override.
- For first-hop delivery in ambient mode, set `[ambient].seed_peers` in config.
- Local post acceptance, semantic matches, and outbound delivery are shown separately in compose results.

Client GUI model (AGI2-aligned):
- `Post + Search`: single primary box where posting adds a message and returns related messages; search lists matching pool entries.
- `Results`: ranked related/matching messages with sender/timestamp and route-explanation drawer (`Why did I see this?`).
- `Thread`: conversation-style chain view with route/provenance details and reply-by-posting workflow.
- `Identity & Keys`: browser-local identity profiles and per-peer signing preferences (router key material remains pairwise and managed by router protocol flows).
- `Inbox`: routed-back message feed with sender/body filters.

## Build From Source

```bash
cargo build --workspace --release
```

## Test

```bash
cargo test --workspace --locked
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
- `crates/cmr-peer/tests/docker_smtp.rs`:
  - dockerized MailHog integration to verify SMTP preserves arbitrary binary payload bytes.

## Dependency and Advisory Hygiene

Commands used to keep dependency graph and security state clean:

```bash
cargo update --verbose
~/.cargo/bin/cargo +nightly udeps --all-targets --all-features
~/.cargo/bin/cargo +nightly miri test -p cmr-core --lib
cargo audit
cargo deny check advisories bans licenses sources --config deny.toml
```

CI runs a full platform matrix (Linux GNU + musl, macOS, Windows, FreeBSD/OpenBSD/NetBSD on x86_64 + ARM64), with workspace tests on each target, plus dedicated Linux Docker SMTP integration, nightly `udeps`, nightly `miri`, security audit/deny, and CodeQL.

## Run From Source

```bash
cargo run -p cmr-peer -- init-config --config cmr-peer.toml
cargo run -p cmr-peer -- run --config cmr-peer.toml
cargo run -p cmr-peer -- self-test --config cmr-peer.toml --spawn-runtime
```

## Notes

- SMTP inbound can be handled by the built-in `[listen.smtp]` listener or by your MTA piping to `receive-stdin`.
- For HTTPS listener, provide PEM cert/key paths in config.
- Use pairwise unique shared keys per peer.
- Mahoney's V2.2 paper seemingly includes an error suggesting insecure raw SHA256 usage. We do not implement that error. We use `HMAC-SHA256` for message authentication (not raw `SHA256(key || message)`), and `HKDF-SHA256` to derive keys from RSA/DH shared secrets.

## A1 Role Boundary

- Router forwarding stays A1-pure: it forwards existing messages and does not emit newly constructed wire messages.
- When protocol control traffic is needed (for example first-contact key exchange), the router emits a `ClientMessagePlan` and the peer daemon client layer (`send_client_plan`) materializes/sends it.
- Extensibility: alternate clients can consume `ClientMessagePlan` and apply custom send scheduling/retry/transport policy without changing core router semantics.


## TODO

- [Economic incentives](https://mattmahoney.net/agi2.html#:~:text=4%2E%20Security%20and%20Economic%20Considerations)

- [Long Term Safety & Intelligent Worm Hardening](https://mattmahoney.net/agi2.html#:~:text=5%2E%20Long%20Term%20Safety%20of%20AGI)
