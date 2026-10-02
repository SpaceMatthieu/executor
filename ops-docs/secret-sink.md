# Secret-sink — enrollment and FAKE queue protocol (prototype)

Status: FAKE-only scaffold for review. No real Tailscale mint. No secrets in GitHub.

## Enrollment (explicit, reimage-safe)

- Box generates `deviceId` and an HMAC `secret` locally (or server issues once).
- One-shot `enrollDevice` ceremony registers the device with Executor.
  - Server stores the credential under Executor + 1Password (future live path).
  - The model only ever sees `{ ok, deviceId, credentialId }` — never the secret.
- After a wipe: the credential is gone; the box must re-enroll explicitly.

Tool sketch:

```json
// executor.secretSink.enrollDevice (FAKE-only)
{ "deviceId": "dev-12345" } -> { "ok": true, "deviceId": "dev-12345", "credentialId": "fake-credential:dev-12345" }
```

## Run on box (dry-run only in this pass)

```json
// executor.secretSink.runOnBox
{
  "action": "tailscale.join",
  "hostname": "dynamik-ops-grokbot",
  "tags": ["tag:grok-ops"],
  "dryRun": true,
  "authKeyFrom": {
    "connection": "tailscale_api.user.dynamikTailscale",
    "op": "keys.createKey",
    "params": { "capabilities": { "devices": { "create": { "tags": ["tag:grok-ops"] } } } }
  }
}
-> { "joined": false, "hostname": "dynamik-ops-grokbot", "dryRun": true }
```

Forbidden in inputs/outputs/logs: `authKey`, `tskey-*`, any bearer/API token, or secret values.

## Poll protocol (future live)

Canonical endpoints (future live under `https://executor.sh`; FAKE loopback prototype uses `http://127.0.0.1:18766`):

- POST `/v1/secret-sink/jobs` — enqueue (no key fields in JSON)
- GET `/v1/secret-sink/jobs/claim` — device HMAC claims pending jobs
- POST `/v1/secret-sink/jobs/{id}/result` — device reports sink outcome
- GET `/v1/secret-sink/jobs/{id}` — wait/poll status
- GET `/v1/health` — liveness

Device HMAC headers:

- `X-Secret-Sink-Device: <deviceId>`
- `X-Secret-Sink-Date: <unix-seconds>`
- `X-Secret-Sink-Signature: hex(HMAC-SHA256(secret, METHOD + "\\n" + path + "\\n" + date + "\\n" + sha256(body)))`
- `X-Secret-Sink-Credential-Id: <credentialId>` (audit only)

Job JSON allowlist (no secrets):

```json
{ "action": "tailscale.join", "hostname": "box", "tags": ["tag:grok-ops"], "dryRun": true, "sealed": { "kind": "fake" } }
```

Result JSON (no secrets):

```json
{ "joined": false, "dryRun": true, "hostname": "box", "ok": true }
```

