# Wily Gatekeeper — Proof Gatekeeper agent (Agent Games / zkVerify)

A deterministic, fail-closed agent for the **Proof Gatekeeper** track of
[Agent Games](https://agentgames.zkverify.io/events/proof-gatekeeper)
(zkVerify AI Agent Competition, 2026-10-21 – 2026-11-21).

The agent receives a proof-backed payment task, checks it against the 7
documented trap varieties, and returns a signed `APPROVE` / `REJECT`
decision. It never approves a task it cannot independently confirm.

## How it decides

For each task (`type: agent-games.proof-gatekeeper.v1`) the agent applies the
field checks in trap-encyclopedia order (`lib/decide.js`):

| # | Check | Result |
|---|-------|--------|
| 1 | `proof_vk != registered_vk` | `REJECT / VK_SUBSTITUTION` |
| 2 | `public_balance < minimum` | `REJECT / THRESHOLD_MISMATCH` |
| 3 | `proof_tx` already in the seen-set | `REJECT / PROOF_REUSED` |
| 4 | `current_block > expiry_block` | `REJECT / EXPIRED_CONDITION` |
| 5 | `recipient != condition_recipient` | `REJECT / RECIPIENT_MISMATCH` |
| 6 | `amount > max_transfer` | `REJECT / AMOUNT_OVERFLOW` |
| 7 | all checks pass | see proof confirmation below |

If all field checks pass, the agent confirms the incoming proof via
**Kurier** (`GET /job-status/{API_KEY}/{proof_tx}`) and only then approves.
If the proof cannot be confirmed (no `KURIER_API_KEY`, Kurier unreachable,
or the reference is not a Finalized/IncludedInBlock job) it **fails closed**
and returns `REJECT / PROOF_NOT_CONFIRMED` instead of approving blind.
`PROOF_NOT_CONFIRMED` is not one of the 7 documented codes; it is only used
on this fail-closed path.

On `APPROVE` the agent also generates a local **Groth16** decision proof
with `snarkjs` and the event circuit, and includes it in the response
(`proof`, `publicSignals`, `vkHash`). The proof is re-verified locally
before it is sent; if it cannot be generated/verified the response still
carries the correct decision, just without a proof (the platform scores the
decision; the proof bonus is lost, never faked).

Every response — including errors — is signed with
`x-agent-games-signature` (HMAC-SHA256 over the raw response body).

The seen-set of `proof_tx` values is persisted to disk (`data/seen.json`)
so `PROOF_REUSED` detection survives restarts. A `proof_tx` is added to the
seen-set only when the task is approved.

## Circuit

Gatekeeper circuit (Groth16 / BN128, Circom 2.x), from
`https://agentgames.zkverify.io/api/circuit-info`:

- `vkHash`: `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `wasm`: `circuits/gatekeeper.wasm`
- `zkey`: `circuits/gatekeeper_final.zkey`
- 13 public inputs (all public, discovered by probing the WASM):
  `taskId, decision, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, registeredVkHash,
  proofVkHash, salt`
- Encoding (`lib/prove.js`): `taskId = keccak256(task_id)`,
  `decision = 1` for APPROVE / `0` for REJECT, addresses and VK hashes as
  field elements, `salt` = fresh random field element per proof.
  **Validated 2026-11-15:** a proof generated for a valid task (APPROVE)
  verifies locally (`snarkjs.groth16.verify` → `true`, ~1.2s), and a
  REJECT proof (VK mismatch) also verifies. See `prove-experiment.log`.
  Note: alternate encodings (numeric taskId, keccak VK) also verify locally,
  so the circuit does not pin the encoding — the platform's expected
  encoding is what matters. `PROOF_TASK_ID_MODE` / `PROOF_VK_MODE` switch it.

## Run

Requirements: Node.js 20+ (tested on Node v24).

```bash
npm install
cp .env.example .env   # then fill in the real values (see below)
node server.js
```

Environment variables:

| Var | Required | Notes |
|-----|----------|-------|
| `PORT` | no (default `3000`) | listen port |
| `AGENT_GAMES_HMAC_SECRET` | **yes** (unless `ALLOW_UNSIGNED=1`) | HMAC secret from the Agent Games dashboard ("Rotate Secret"). Never a local placeholder. |
| `ALLOW_UNSIGNED` | no | `1` = accept unsigned tasks. **Local testing only.** |
| `KURIER_API_KEY` | **yes, for approvals** | Kurier mainnet API key. Without it the agent fails closed and never approves. |
| `KURIER_API_URL` | no (default `https://api.kurier.xyz/api/v1`) | Kurier base URL |
| `VK_HASH` | no (default = gatekeeper vkHash above) | circuit vkHash included in responses |
| `WASM_PATH` / `ZKEY_PATH` | no (default `circuits/...`) | circuit artifacts |
| `SEEN_FILE` | no (default `./data/seen.json`) | persistent seen-set |
| `SUBMIT_PROOF_TO_KURIER` | no (default `0`) | `1` = also submit the local decision proof to Kurier (fire-and-forget, never blocks the 60s response) |
| `PROOF_TASK_ID_MODE` | no (default `keccak`) | `keccak` or `numeric` |
| `PROOF_VK_MODE` | no (default `raw`) | `raw` or `keccak` |

Endpoints:

- `GET /health` → `200 {"status":"ok", ...}` (platform health check, no auth)
- `POST /` (also `/agent`, `/task`) → task handler. Requires a valid
  `x-agent-games-signature` HMAC over the raw body (unless `ALLOW_UNSIGNED=1`).
  Responds `{decision, reason_code, proof_tx[, proof, publicSignals, vkHash]}`.

## Test

```bash
node test/test.js
```

Spawns the server on port 3456 with a test HMAC secret and runs 19 checks:
the valid case (pure logic → `APPROVE/VALID_CONDITION`), one mutated
variant per trap type (all 6 → correct `REJECT` code), the fail-closed
valid case with no Kurier key (`REJECT/PROOF_NOT_CONFIRMED`), HMAC
failures (missing / wrong / tampered → 401), response signing, and the
health endpoint. Exits non-zero on any failure.

Proof-encoding experiment:

```bash
node prove-experiment.js
```

Generates a Groth16 proof for a valid task (APPROVE) and for a
VK-mismatch task (REJECT) and reports whether each verifies locally.

## Public HTTPS endpoint (tunnel)

The platform requires a public HTTPS endpoint. This VM has no direct
outbound internet (egress only through an authenticated HTTP proxy), so the
bundled `tunnel-lt.js` runs [localtunnel](https://localtunnel.me) through
that proxy (it patches `net.connect`/`net.createConnection` to route
non-local TCP via HTTP CONNECT, and sets an `HttpsProxyAgent` on the shared
axios instance for the tunnel-registration request).

```bash
node tunnel-lt.js [subdomain]   # e.g. node tunnel-lt.js wily-gatekeeper
```

Keep it running; the URL (`https://<name>.loca.lt`) is only valid while it
runs. **Known limitation (2026-11-15):** the tunnel establishes and prints
a URL, but requests to the public URL returned `503 Tunnel Unavailable`
from localtunnel.me (and an empty response on a random subdomain) — the
data plane did not forward to the local agent from this VM. Do **not**
register that URL until a health check through the public URL returns
`{"status":"ok"}`. The reliable path is to deploy this code on a host with
direct internet (e.g. Fly.io / Render / Railway) and register that URL.

## Security notes

- No secrets are hardcoded. All secrets come from env vars. Never commit
  `.env` (it is gitignored) or any API key / HMAC secret / private key.
- The HMAC secret must be the platform-generated value from the dashboard
  ("Rotate Secret"). A local placeholder will fail the platform's checks.
- The agent fails closed: uncertain input, unconfirmed proof, malformed
  payload, or any unexpected error all produce a `REJECT`, never an approval.
- The local Groth16 proof is generated from the task fields only; it does
  not contain or leak any secret.

## Repo

Public repo (to be created on the owner's personal GitHub account):
`willyhoki/wily-gatekeeper`. This directory is the clean source for that
repo — do not commit `node_modules/`, `.env`, or `data/seen.json`
(see `.gitignore`).
