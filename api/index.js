// api/index.js — Proof Gatekeeper agent as a Vercel Serverless Function.
//
// Same decision flow as server.js (HMAC verify over the RAW body -> 7 trap
// checks in lib/decide.js -> Kurier proof confirmation -> local Groth16
// decision proof -> signed response), adapted for Vercel's stateless,
// serverless runtime:
//
//   * No listening socket: Vercel invokes `module.exports` per request.
//   * Raw body: read from the request stream (NOT req.body). Vercel's Node
//     runtime does not pre-parse the body for plain Serverless Functions, so
//     the stream IS the raw bytes the platform signed. HMAC is verified over
//     those bytes before any JSON parsing — exactly like server.js.
//   * Seen-set: an in-memory, module-level Set (see below). It survives
//     between warm invocations of the same instance only.
//   * No ALLOW_UNSIGNED: an HMAC secret is mandatory. If it is missing the
//     function fails closed (401) instead of starting.
//
// Env vars (set in the Vercel dashboard, never committed):
//   AGENT_GAMES_HMAC_SECRET  REQUIRED — from the Agent Games dashboard
//                            ("Rotate Secret").
//   KURIER_API_KEY           Kurier mainnet API key. Without it the agent
//                            fails closed (never approves) — same as server.js.
//   KURIER_API_URL           Kurier base URL (default https://api.kurier.xyz/api/v1)
//   VK_HASH                  gatekeeper circuit vkHash (default from
//                            /api/circuit-info)
//   PROOF_TASK_ID_MODE       'keccak' (default) or 'numeric'
//   PROOF_VK_MODE            'raw' (default) or 'keccak'
//   SUBMIT_PROOF_TO_KURIER   "1" = also submit the local decision proof to
//                            Kurier (fire-and-forget; on Vercel the function
//                            may freeze after the response, so this is
//                            best-effort only). Default "0".
//
// Routes (see vercel.json rewrites — every route lands here):
//   GET  /  /health  /healthz  -> 200 {"status":"ok", ...} (no auth)
//   POST /  /agent  /task      -> task handler (HMAC required)
//   anything else              -> 405 / 404
//
// Vercel Hobby limit is 10s per invocation. Worst case here is roughly:
// cold start (~1-2s) + Kurier confirm (~1-2s) + Groth16 fullProve (~1.2s)
// + local verify (~0.5s) — comfortably inside the limit. No extra slow
// work is added on this path.

const path = require('path');
const { verifyHmac, signBody } = require('../lib/hmac');
const { decide, REASONS } = require('../lib/decide');
const kurier = require('../lib/kurier');
const { generateProof } = require('../lib/prove');

const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const WASM_PATH = process.env.WASM_PATH || path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = process.env.ZKEY_PATH || path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');
const VK_HASH = process.env.VK_HASH || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const SUBMIT_PROOF_TO_KURIER = process.env.SUBMIT_PROOF_TO_KURIER === '1';
const PROOF_OPTS = {
  taskIdMode: process.env.PROOF_TASK_ID_MODE || 'keccak',
  vkMode: process.env.PROOF_VK_MODE || 'raw',
};

// ---------------------------------------------------------------------------
// Seen-set: BEST-EFFORT ONLY on Vercel.
// ---------------------------------------------------------------------------
// Vercel Serverless Functions are stateless: there is no shared disk, and
// each cold start (or scale-out to a second instance) starts with an EMPTY
// set. This module-level Set survives only between warm invocations of the
// SAME instance. Consequence, stated honestly: a PROOF_REUSED task CAN slip
// through as APPROVE if its first approval happened on a different/cold
// instance (the platform scores that as a wrong APPROVE, -6). The file-based
// seen-set in server.js (data/seen.json) does not have this hole — this is
// the price of the free, card-free Vercel Hobby tier. The trap checks that
// do NOT depend on memory (VK, threshold, expiry, recipient, amount) are
// unaffected, and every APPROVE still requires independent Kurier proof
// confirmation, so a reused proof still has to be a real, finalized proof.
// Do NOT pretend this is equivalent to the persistent seen-set.
const _seen = new Set();
const seen = {
  has: (tx) => _seen.has(String(tx)),
  add: (tx) => { _seen.add(String(tx)); },
  size: () => _seen.size,
};

function log(taskId, msg, extra) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${taskId || '-'}] ${msg}${extra ? ' ' + JSON.stringify(extra) : ''}`);
}

// Read the RAW request body as a Buffer. Handles three cases:
//   1. req.body already a Buffer/string (some runtimes pre-buffer) — use it.
//   2. req is a readable stream (normal Vercel Node case) — collect chunks.
//   3. req.body already parsed into an object — Vercel pre-parses JSON
//      bodies and the `bodyParser: false` config is not honoured for this
//      plain Serverless Function, so the exact raw bytes are unrecoverable.
//      FALLBACK: re-serialize with JSON.stringify. This reproduces the
//      original bytes ONLY if the platform sent compact JSON (no spaces)
//      with keys in the same order JSON.parse preserved — which is the
//      common case (the platform's preflight/task payloads are compact).
//      If the re-serialized bytes differ, HMAC verification fails closed
//      (401) rather than accepting a wrong body. This fallback is what
//      makes the endpoint work on Vercel at all; the stream path (case 2)
//      is still preferred whenever the runtime leaves the body unparsed.
async function readRawBody(req) {
  if (Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === 'string') return Buffer.from(req.body, 'utf8');
  if (req.body !== undefined && req.body !== null) {
    try {
      return Buffer.from(JSON.stringify(req.body), 'utf8');
    } catch {
      return null;
    }
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

// Send a JSON response signed with x-agent-games-signature over the exact
// raw body string that is sent (same convention as server.js).
function sendSigned(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.setHeader('content-type', 'application/json');
  if (HMAC_SECRET) res.setHeader('x-agent-games-signature', signBody(HMAC_SECRET, body));
  res.statusCode = statusCode;
  res.end(body);
}

// Task handler — mirrors server.js handleTask() step for step (fail closed
// at every step). Returns via sendSigned; the returned object is only for
// logging.
async function handleTask(rawBody, req, res) {
  const started = Date.now();
  // 1. HMAC over the RAW body, before parsing.
  const sig = req.headers['x-agent-games-signature'] || req.headers['x-signature'] || '';
  if (!HMAC_SECRET) {
    sendSigned(res, 401, { error: 'hmac secret required' });
    return { taskId: null, logMsg: 'no HMAC secret configured — fail closed' };
  }
  if (!verifyHmac(HMAC_SECRET, rawBody, sig)) {
    sendSigned(res, 401, { error: 'invalid signature' });
    return { taskId: null, logMsg: 'HMAC verification failed — rejected before parsing' };
  }

  // 2. Parse. A signed request that is NOT a gatekeeper task is the
  // platform's preflight/protocol probe. It must be answered with the
  // signed protocol-v1 handshake {"ok":true,"protocolVersion":"v1"} —
  // NOT with a task decision and NOT with a 4xx. (The diagnostic says:
  // "Return signed protocol-v1 JSON — {"ok":true,"protocolVersion":"v1"}
  // — with a valid x-agent-games-signature header computed from your
  // HMAC secret.")
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch (e) {
    // Not JSON (e.g. empty preflight body) — answer the handshake.
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    return { taskId: null, logMsg: 'non-JSON body — protocol handshake' };
  }
  const taskId = envelope.task_id || (envelope.input && envelope.task_id) || null;
  const inputForType = envelope.input || envelope;
  const hasTaskFields = Boolean(
    inputForType.task_id || inputForType.proof_tx || inputForType.registered_vk
  );
  if (envelope.type && envelope.type !== 'agent-games.proof-gatekeeper.v1') {
    // A different type (e.g. the preflight probe) — handshake, not a task.
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    return { taskId, logMsg: `non-task type ${envelope.type} — protocol handshake` };
  }
  if (!envelope.type && !hasTaskFields) {
    // No type and no task fields — a preflight probe, not a task.
    sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
    return { taskId, logMsg: 'no task fields — protocol handshake' };
  }
  const input = envelope.input || envelope;
  const taskInput = { ...input, task_id: input.task_id || taskId || '' };
  const proofTx = String(taskInput.proof_tx || '');

  // Task deadline: if the platform's deadline has passed, the task is stale.
  if (envelope.deadline_at) {
    const dl = Date.parse(envelope.deadline_at);
    if (!Number.isNaN(dl) && Date.now() > dl) {
      sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.EXPIRED, proof_tx: proofTx });
      return { taskId, logMsg: 'task deadline passed — REJECT/EXPIRED_CONDITION' };
    }
  }

  // 3. The 7 field checks.
  let verdict;
  try {
    verdict = decide(taskInput, seen);
  } catch (e) {
    // Malformed input -> fail closed.
    sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.UNCONFIRMED, proof_tx: proofTx });
    return { taskId, logMsg: `malformed input (${e.message}) — fail-closed REJECT` };
  }

  if (verdict.decision === 'REJECT') {
    sendSigned(res, 200, { decision: 'REJECT', reason_code: verdict.reason_code, proof_tx: proofTx });
    return { taskId, logMsg: `REJECT/${verdict.reason_code} (${verdict.detail})` };
  }

  // 4. All field checks pass -> confirm the incoming proof before approving.
  const conf = await kurier.confirmProof(proofTx);
  if (!conf.confirmed) {
    sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.UNCONFIRMED, proof_tx: proofTx });
    return { taskId, logMsg: `proof NOT confirmed (${conf.detail}) — fail-closed REJECT` };
  }
  log(taskId, `proof confirmed (${conf.detail})`);

  // 5. Generate the local Groth16 decision proof (best effort; never fake one).
  const proofRes = await generateProof({
    input: taskInput,
    decision: 'APPROVE',
    wasmPath: WASM_PATH,
    zkeyPath: ZKEY_PATH,
    opts: PROOF_OPTS,
    verify: true,
  });
  if (!proofRes.available) {
    log(taskId, `local proof unavailable: ${proofRes.reason} — responding APPROVE without proof`);
  } else if (SUBMIT_PROOF_TO_KURIER) {
    // Fire-and-forget: do not block the 60s response. NOTE: on Vercel the
    // function may freeze right after the response is sent, so this submit
    // may never complete — best-effort only.
    kurier.submitProof({ proof: proofRes.proof, publicSignals: proofRes.publicSignals, vkHash: VK_HASH })
      .then((r) => log(taskId, `kurier submit-proof: ${r.jobId ? 'jobId ' + r.jobId : 'error ' + r.error}`))
      .catch((e) => log(taskId, `kurier submit-proof threw: ${e.message}`));
  }

  // 6. APPROVE: record the proof_tx in the in-memory seen-set (best-effort,
  // see the big comment at the top of this file).
  seen.add(proofTx);

  const body = { decision: 'APPROVE', reason_code: REASONS.VALID, proof_tx: proofTx };
  if (proofRes.available) {
    body.proof = proofRes.proof;
    body.publicSignals = proofRes.publicSignals;
    body.vkHash = VK_HASH;
  }
  sendSigned(res, 200, body);
  return { taskId, logMsg: `APPROVE/VALID_CONDITION in ${Date.now() - started}ms${proofRes.available ? ' + local proof' : ' (no local proof)'}` };
}

// Vercel Serverless Function entrypoint (CommonJS — package.json has no
// "type": "module", and lib/* are CommonJS).
module.exports = async (req, res) => {
  try {
    const url = req.url || '/';
    const pathname = url.split('?')[0];

    // Health check (no auth). GET / is also health: the platform may probe
    // the registered endpoint URL itself, and server.js 405s GET / — on
    // Vercel the root URL is the natural health-check target, so answer ok.
    if (req.method === 'GET' && (pathname === '/' || pathname === '/health' || pathname === '/healthz')) {
      res.setHeader('content-type', 'application/json');
      res.statusCode = 200;
      res.end(JSON.stringify({ status: 'ok', seen: seen.size(), kurier: kurier.configured() }));
      return;
    }

    if (req.method !== 'POST') {
      sendSigned(res, 405, { error: 'method not allowed' });
      return;
    }
    if (pathname !== '/' && pathname !== '/agent' && pathname !== '/task' && pathname !== '/api/index') {
      sendSigned(res, 404, { error: 'not found' });
      return;
    }

    const rawBody = await readRawBody(req);
    if (rawBody === null) {
      // Body was pre-parsed by the runtime: raw bytes unrecoverable, so the
      // HMAC cannot be verified — fail closed rather than guess.
      sendSigned(res, 401, { error: 'raw body unavailable' });
      log(null, 'request body was pre-parsed by the runtime — fail closed');
      return;
    }

    const { taskId, logMsg } = await handleTask(rawBody, req, res);
    log(taskId, logMsg);
  } catch (e) {
    console.error('[error] handler threw:', e);
    // Fail closed even on an unexpected error.
    try { sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.UNCONFIRMED, proof_tx: '' }); } catch { /* socket gone */ }
  }
};

// CRITICAL: Vercel pre-parses JSON request bodies into req.body by default.
// That destroys the raw bytes the platform signed, so HMAC verification
// would always fail closed with "raw body unavailable" (HTTP 401). This
// config disables the body parser so the handler receives the raw request
// stream and can verify the HMAC over the exact signed bytes (same
// requirement as a Stripe webhook signature).
// NOTE: the config MUST be set AFTER `module.exports = ...` above —
// assigning module.exports replaces the object, so a config set before it
// would be silently discarded.
module.exports.config = { api: { bodyParser: false } };
