# Upstream tracking

Source: [Flowseal/tg-ws-proxy v1.10.2](https://github.com/Flowseal/tg-ws-proxy/tree/v1.10.2),
commit `f200e33fd283143a9f101d62aaf9d8c1468a23fe`, 2026-09-07.
Verified against both GitHub latest-release API and `git ls-remote` on 2026-09-14.
The Go port in Omn1z/nfqws2-keenetic-strategy-selector was a second reference,
including its protocol vectors and router-specific compatibility findings.

| Upstream network behavior | Rust implementation |
|---|---|
| Authenticated obfuscated transport, AES CTR streams | `src/crypto.rs` |
| Fake TLS HMAC, timestamp and TLS record framing | `src/fake_tls.rs`, `src/proxy.rs` |
| Abridged/intermediate/padded MTProto packet boundaries | `src/framing.rs`, `src/proxy.rs` |
| WS client masking, fragmentation, ping/pong, frame bounds | `src/websocket.rs` |
| Test DC 10000 offset, negative media DC, test WS path | `src/proxy.rs`, `src/upstream.rs` |
| DC redirects, timeout cooldown and redirect blacklist | `src/upstream.rs` |
| CF proxy/Worker domain lists, preferred working domain | `src/upstream.rs` |
| Domain refresh, retain last good list on fetch/validation failure | `src/upstream.rs` |
| WS pool expiry, health check, retry backoff | `src/upstream.rs` |
| PROXY v1, masking relay, cleanup on listener restart | `src/proxy.rs` |

Intentional router adaptations:

- No desktop GUI/tray, Python runtime, Python package installer or desktop updater.
  Static web assets are compiled into the executable; procd/Entware and a shell
  release installer own process lifecycle and updates.
- One Tokio runtime thread, bounded clients/buffers. Optional pooling defaults
  to zero, serial background TLS dials, worker warm sockets capped per DC.
- MTProto framing uses four bytes of plaintext header and streams the payload.
  It does not retain both encrypted and decrypted whole-message buffers.
- SNI fronting is opt-in following the Go router port: some networks complete
  HTTP Upgrade on a front but never return MTProto traffic.
- Direct Telegram TLS retains upstream's permissive certificate behavior for
  IP/domain fronting. CF and GitHub refresh use normal certificate verification.
- Strict WS Upgrade proof/headers, bounded HTTP headers/body, Basic Auth, CSRF and
  Host checks. Fake TLS includes a bounded replay cache beyond upstream's HMAC
  timestamp window.
- Single-field legacy CF configuration is migrated; explicitly present arrays
  win. Unknown historical settings survive JSON saves but are not executed.
- Standalone logs go to the supervisor, not a Python rotating-file logger.
  The panel links to releases and shows the update command; it never executes
  a remote installer as part of an HTTP request.

Synchronization means the listed network behaviors were ported and covered by
local protocol tests. It is not a claim that every upstream desktop feature or
every possible Telegram/network/router combination has been tested. Before a
production release run the cross/QEMU matrix and exercise real Telegram on the
target router with direct WS, CF/Worker and Fake TLS as applicable.

For the next update, compare upstream `proxy/`, `tests/` and
`.github/cfproxy-domains.txt`; port relevant changes, add regression tests and
update this revision together with the constants in `src/config.rs`.
