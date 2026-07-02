# UADP message-security golden vectors (OPC UA Part 14 §7.2.4.4)

Checked-in fixtures for secured UADP NetworkMessages. Every vector is a pair of files:

- `<name>.bin` — the complete secured NetworkMessage exactly as it appears on the wire
  (header, SecurityHeader, payload region — ciphertext when the mode is SignAndEncrypt —
  and the trailing 32-byte HMAC-SHA256 signature).
- `<name>.keys.json` — everything needed to verify and decrypt it:

  | Field               | Meaning                                                              |
  |---------------------|----------------------------------------------------------------------|
  | `description`       | Human-readable summary of the message content and construction.      |
  | `source`            | `computed` for vectors derived from the spec tables; use the emitting implementation name (e.g. `open62541`, `opclabs`) for captured vectors. |
  | `mode`              | `Sign` or `SignAndEncrypt` (`MessageSecurityMode` enum literal).      |
  | `securityPolicyUri` | `PubSub-Aes128-CTR` or `PubSub-Aes256-CTR` policy URI.                |
  | `signingKey`        | Hex, 32 bytes (HMAC-SHA2-256 key, Part 14 Table 155).                 |
  | `encryptingKey`     | Hex, 16 (Aes128) or 32 (Aes256) bytes.                                |
  | `keyNonce`          | Hex, 4 bytes (Table 155).                                             |
  | `messageNonce`      | Hex, 8 bytes — the nonce inside the `.bin` SecurityHeader, recorded for provenance (Random[4] followed by the UInt32 LE nonce sequence number, Table 156). |
  | `tokenId`           | The SecurityTokenId inside the `.bin` SecurityHeader (integer).       |

`SecurityVectorFixturesTest` (in `org.eclipse.milo.opcua.sdk.pubsub.uadp`, test tree)
discovers every `*.bin` in this directory and asserts a successful verified decode with a
static resolver built from the companion `.keys.json` — drop a new pair in and it is
covered automatically. Vectors with `"source": "computed"` additionally get bit-exact
Milo-encoder reproduction and exact decoded-field assertions.

## Provenance of the `computed-*` vectors

Fixed inputs (shared by `UadpSecurityCodecTest`): signingKey `00..1f`, encryptingKey
`40..4f`/`40..5f`, keyNonce `a0a1a2a3`, messageNonce `deadbeef01000000` (Random
`deadbeef`, sequence number 1), tokenId 3, PublisherId Byte 42, one Variant-encoded key
frame (Int32 42, Boolean true) from DataSetWriterId 1. The plaintext layout is
hand-derived byte by byte from Part 14 v1.05 Table 154/156 and Annex A.2.1.5 (sign-only
carries a real token + 8-byte nonce); AES-CTR uses the Table 157 counter block
`keyNonce || messageNonce || 00000001`.

The `.bin` bytes were generated and are independently verified — without any Milo
code — by `milo-pubsub-notes/captures/check-phase4-vectors.py` (Python stdlib
hmac/hashlib for HMAC-SHA256; AES-CTR via the openssl CLI, cross-checked against the
`cryptography` package). Run `python3 check-phase4-vectors.py` to re-verify; it prints
PASS/FAIL per vector with byte diffs on mismatch.

## Adding captured vectors (K20)

The scripted capture procedure (peer configs, fixed key material, per-cell verification)
is `milo-pubsub-notes/interop-fleet/RUNBOOK-SECURED.md`; no third-party captures have been
promoted yet — the `computed-*` vectors are currently the only fixtures here.

Capture one secured NetworkMessage (UDP datagram payload, exactly the NM bytes) from a
peer configured with known static keys — e.g. open62541 `pubsub_publish_encrypted` with
its static key arrays patched to a fixed pattern, or OPC Labs UADemoPublisher with a
`static:?key=...` 52/68-byte key. Save it as `<source>-<mode>-<policy>.bin`
(e.g. `open62541-signandencrypt-aes128ctr.bin`), record the exact keys, token id, and
the nonce the message carries in the companion `.keys.json`, and set `source`
accordingly. A capture is valid forever because all inputs (bytes, keys) are pinned.
