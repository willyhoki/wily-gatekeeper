# Vercel deployment — Proof Gatekeeper agent

Serverless adaptation of the Gatekeeper agent for **Vercel Hobby (free, no
card)**. Same decision flow as `server.js`; only the hosting shape changed.
See `api/index.js` for the code and the big comment about the seen-set.

## Deploy (from your phone)

1. Open https://vercel.com and sign up / log in with **GitHub**
   (button "Continue with GitHub"). The Hobby plan is free and does not ask
   for a card.
2. **Add New… > Project** > **Import** the repository
   `willyhoki/wily-gatekeeper` (if it is not listed, click "Adjust GitHub
   App Permissions" and grant access to that repo).
3. On the "Configure Project" screen:
   - **Framework Preset:** `Other` (this is plain Node.js, not Next.js).
   - **Build Command:** leave empty (no build step needed).
   - **Output Directory:** leave empty.
   - **Install Command:** leave as default (`npm install`).
   - **Root Directory:** leave as `./`.
4. **Environment Variables** — add these two (required):
   - `AGENT_GAMES_HMAC_SECRET` = the secret from your Agent Games dashboard
     ("Rotate Secret"). Get it AFTER registering the agent (see step 6).
     The function refuses every task (401) without it.
   - `KURIER_API_KEY` = your Kurier mainnet API key (free, from kurier.xyz).
     Without it the agent fails closed and never approves — it can still
     correctly REJECT all 6 trap types, but it cannot score the ~50% of
     tasks that are valid approvals.
   - Optional, only if you need them: `KURIER_API_URL`,
     `PROOF_TASK_ID_MODE`, `PROOF_VK_MODE`, `SUBMIT_PROOF_TO_KURIER`.
     `PORT` is NOT needed — Vercel assigns the port itself.
5. Click **Deploy**. Wait until the status is **Ready** (usually 1–3 min).
6. Copy the deployment URL, e.g. `https://wily-gatekeeper.vercel.app`.
   Test it in your browser:
   - `https://<your-url>/health` must show `{"status":"ok",...}`.
7. Register the agent at https://agentgames.zkverify.io:
   - Agent name: `Wily`
   - Track: Proof Gatekeeper only
   - Repository URL: `https://github.com/willyhoki/wily-gatekeeper`
   - Agent Endpoint: your Vercel URL from step 6
8. Back in the Agent Games dashboard, copy the HMAC secret ("Rotate
   Secret"), paste it as `AGENT_GAMES_HMAC_SECRET` in Vercel
   (Project > Settings > Environment Variables), then **Redeploy**
   (Deployments > … > Redeploy) so the function picks it up.
9. In the Agent Games dashboard, complete the signed preflight + at least
   1 practice task. Then the agent is ready for the rounds.

## How it works on Vercel

- `api/index.js` is a Vercel Serverless Function (CommonJS). `vercel.json`
  rewrites `/`, `/health`, `/healthz`, `/agent`, `/task` to it.
- The request body is read raw from the stream and the HMAC
  (`x-agent-games-signature`) is verified over those raw bytes before any
  JSON parsing — exactly like `server.js`.
- The 7 trap checks (`lib/decide.js`), Kurier confirmation
  (`lib/kurier.js`) and the local Groth16 proof (`lib/prove.js`, circuits in
  `circuits/`) are the same code as the standalone server. The circuit
  files (`gatekeeper.wasm` ~1.7 MB, `gatekeeper_final.zkey` ~310 KB) are
  committed in the repo and read from the filesystem at runtime.
- Responses are signed with `x-agent-games-signature` over the raw
  response body, same as `server.js`.

## Honest limitations (read this before relying on it)

1. **Seen-set is best-effort only.** Vercel functions are stateless: there
   is no shared disk, and every cold start (or scale-out to a second
   instance) starts with an EMPTY seen-set. A `PROOF_REUSED` task can
   therefore slip through as APPROVE if its first approval happened on a
   different/cold instance (scored as a wrong APPROVE, −6). The file-based
   seen-set in `server.js` (`data/seen.json`) does not have this hole.
   The other 5 trap checks do not depend on memory and are unaffected, and
   every APPROVE still requires an independent, finalized Kurier proof
   confirmation, so a reused proof still has to be a real proof.
2. **10-second Hobby limit.** Worst case per invocation: cold start
   (~1–2 s) + Kurier confirm (~1–2 s) + Groth16 proof (~1.2 s) + local
   verify (~0.5 s) — comfortably inside 10 s, and well inside the
   platform's 60 s task window. If Vercel ever reports a timeout on an
   APPROVE path, the task is scored −2 (timeout), not a wrong decision.
3. **Fire-and-forget Kurier proof submission is best-effort.** If
   `SUBMIT_PROOF_TO_KURIER=1`, the submit may be cut off when Vercel
   freezes the function after the response. It is off by default and never
   blocks the response.
4. **GET `/` answers health.** Unlike `server.js` (which 405s GET `/`),
   the Vercel function answers `{"status":"ok"}` on GET `/`, because the
   platform may probe the registered endpoint URL itself.
5. **No `ALLOW_UNSIGNED`.** There is no unsigned-test mode on Vercel; a
   missing HMAC secret fails every request closed (401).

## Local tests

- `node test/test-vercel.js` — 12/12 checks pass: GET /health and GET /
  return 200 ok; a valid task with correct HMAC and no Kurier key fails
  closed to REJECT/PROOF_NOT_CONFIRMED with a correctly signed response;
  wrong/missing/tampered HMAC returns 401; VK-mismatch returns
  REJECT/VK_SUBSTITUTION with a signed response; unsupported type 400;
  wrong method 405; unknown path 404.
- `node test/test.js` — the original 19/19 suite for `server.js` is
  unaffected (no changes were made to `server.js` or `lib/*`).
- The local Groth16 proof path (`lib/prove.js` with the same
  circuits resolved from `api/`) generates and locally verifies a proof
  for a valid APPROVE task (see the test run output).
