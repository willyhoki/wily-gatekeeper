// server.js — Proof Gatekeeper agent (Agent Games / zkVerify).
// Plain Node.js http server. No framework, minimal dependencies (snarkjs,
// js-sha3 for keccak). Run:  node server.js
//
// Env vars:
//   PORT                     listen port (default 3000)
//   AGENT_GAMES_HMAC_SECRET  HMAC secret from the platform dashboard
//                            ("Rotate Secret"). REQUIRED unless ALLOW_UNSIGNED=1.
//   ALLOW_UNSIGNED           "1" = accept unsigned tasks (LOCAL TESTING ONLY).
//   KURIER_API_KEY           Kurier mainnet API key. If unset, the incoming
//                            proof cannot be independently confirmed and the
//                            agent FAILS CLOSED (rejects) instead of approving.
//   KURIER_API_URL           Kurier base URL (default https://api.kurier.xyz/api/v1)
//   VK_HASH                  gatekeeper circuit vkHash (default from /api/circuit-info)
//   WASM_PATH / ZKEY_PATH    circuit artifacts (default circuits/gatekeeper.wasm
//                            and circuits/gatekeeper_final.zkey)
//   SEEN_FILE                persistent seen-set path (default ./data/seen.json)
//   PROOF_TASK_ID_MODE       'keccak' (default) or 'numeric'
//   PROOF_VK_MODE            'raw' (default) or 'keccak'
//   SUBMIT_PROOF_TO_KURIER   "1" = also submit the local decision proof to
//                            Kurier (fire-and-forget). Default "0".
//
// Behaviour:
//   GET  /health  -> 200 {"status":"ok"} (platform health check, no auth)
//   POST /  (or /agent, /task) -> task handler (see below)
//
// Task handler (fail closed at every step):
//   1. Read the RAW body. Verify HMAC (x-agent-games-signature) over the raw
//      body BEFORE parsing. Missing/invalid signature -> 401, no processing.
//   2. Parse JSON; require type "agent-games.proof-gatekeeper.v1" and a valid
//      input object. Malformed -> fail-closed REJECT (still signed).
//   3. Apply the 7 field checks (lib/decide.js) in trap-encyclopedia order.
//      Any trap -> REJECT with that reason_code.
//   4. If all field checks pass, confirm the incoming proof via Kurier.
//      Not confirmed -> REJECT / PROOF_NOT_CONFIRMED (never approve blind).
//   5. Generate a local Groth16 decision proof (snarkjs). If it cannot be
//      generated/verified locally, respond with the decision but no proof
//      (the platform scores the decision; the proof bonus is lost, not faked).
//   6. On APPROVE, add proof_tx to the seen-set (persisted to disk).
//   7. Respond {decision, reason_code, proof_tx, proof?, publicSignals?,
//      vkHash?} within the 60s deadline, signed with x-agent-games-signature
//      (HMAC-SHA256 over the raw response body).
//
// The response is always signed when a secret is configured, including error
// responses, so the platform can authenticate every reply.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { verifyHmac, signBody } = require('./lib/hmac');
const { decide, REASONS } = require('./lib/decide');
const { createSeenStore } = require('./lib/seen');
const kurier = require('./lib/kurier');
const { generateProof } = require('./lib/prove');

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const ALLOW_UNSIGNED = process.env.ALLOW_UNSIGNED === '1';
const SEEN_FILE = process.env.SEEN_FILE || path.join(__dirname, 'data', 'seen.json');
const WASM_PATH = process.env.WASM_PATH || path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = process.env.ZKEY_PATH || path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const VK_HASH = process.env.VK_HASH || '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const SUBMIT_PROOF_TO_KURIER = process.env.SUBMIT_PROOF_TO_KURIER === '1';
const PROOF_OPTS = {
  taskIdMode: process.env.PROOF_TASK_ID_MODE || 'keccak',
  vkMode: process.env.PROOF_VK_MODE || 'raw',
};

if (!HMAC_SECRET && !ALLOW_UNSIGNED) {
  console.error('[fatal] AGENT_GAMES_HMAC_SECRET is not set. Set it, or use ALLOW_UNSIGNED=1 for local testing only.');
  process.exit(1);
}
if (!HMAC_SECRET) console.warn('[warn] ALLOW_UNSIGNED=1 — accepting unsigned tasks. LOCAL TESTING ONLY.');

const seen = createSeenStore(SEEN_FILE);
console.log(`[boot] seen-set loaded: ${seen.size()} proof_tx values from ${SEEN_FILE}`);
console.log(`[boot] kurier configured: ${kurier.configured()}`);
console.log(`[boot] circuit wasm: ${WASM_PATH} (${fs.existsSync(WASM_PATH) ? 'present' : 'MISSING'})`);
console.log(`[boot] circuit zkey: ${ZKEY_PATH} (${fs.existsSync(ZKEY_PATH) ? 'present' : 'MISSING'})`);

function log(taskId, msg, extra) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [${taskId || '-'}] ${msg}${extra ? ' ' + JSON.stringify(extra) : ''}`);
}

// Send a signed JSON response (signed whenever a secret is configured).
function sendSigned(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'content-type': 'application/json' };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(HMAC_SECRET, body);
  res.writeHead(statusCode, headers);
  res.end(body);
}

async function handleTask(rawBody, req) {
  const started = Date.now();
  // 1. HMAC over the RAW body, before parsing.
  const sig = req.headers['x-agent-games-signature'] || req.headers['x-signature'] || '';
  if (HMAC_SECRET && !verifyHmac(HMAC_SECRET, rawBody, sig)) {
    return { status: 401, body: { error: 'invalid signature' }, taskId: null, logMsg: 'HMAC verification failed — rejected before parsing' };
  }
  if (!HMAC_SECRET && !ALLOW_UNSIGNED) {
    return { status: 401, body: { error: 'hmac secret required' }, taskId: null, logMsg: 'no HMAC secret configured' };
  }

  // 2. Parse.
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch (e) {
    return { status: 400, body: { error: 'invalid JSON' }, taskId: null, logMsg: 'JSON parse failed' };
  }
  const taskId = envelope.task_id || (envelope.input && envelope.task_id) || null;
  if (envelope.type && envelope.type !== 'agent-games.proof-gatekeeper.v1') {
    return { status: 400, body: { error: 'unsupported task type', decision: 'REJECT', reason_code: REASONS.UNCONFIRMED }, taskId, logMsg: `unsupported type ${envelope.type}` };
  }
  const input = envelope.input || envelope;
  if (input.task_id && !taskId) input.task_id = input.task_id;
  const taskInput = { ...input, task_id: input.task_id || taskId || '' };
  const proofTx = String(taskInput.proof_tx || '');

  // Task deadline: if the platform's deadline has passed, the task is stale.
  if (envelope.deadline_at) {
    const dl = Date.parse(envelope.deadline_at);
    if (!Number.isNaN(dl) && Date.now() > dl) {
      const body = { decision: 'REJECT', reason_code: REASONS.EXPIRED, proof_tx: proofTx };
      return { status: 200, body, taskId, logMsg: 'task deadline passed — REJECT/EXPIRED_CONDITION' };
    }
  }

  // 3. The 7 field checks.
  let verdict;
  try {
    verdict = decide(taskInput, seen);
  } catch (e) {
    // Malformed input -> fail closed.
    const body = { decision: 'REJECT', reason_code: REASONS.UNCONFIRMED, proof_tx: proofTx };
    return { status: 200, body, taskId, logMsg: `malformed input (${e.message}) — fail-closed REJECT` };
  }

  if (verdict.decision === 'REJECT') {
    const body = { decision: 'REJECT', reason_code: verdict.reason_code, proof_tx: proofTx };
    return { status: 200, body, taskId, logMsg: `REJECT/${verdict.reason_code} (${verdict.detail})` };
  }

  // 4. All field checks pass -> APPROVE.
  // NOTE (2026-11-15, Round 3): the old code gated APPROVE on Kurier
  // confirmation via GET /job-status/{API_KEY}/{proof_tx}, treating
  // proof_tx as a Kurier jobId. That can never succeed: a Kurier jobId is
  // a UUID (e.g. '23382e04-3d57-11f0-af7b-32a805cdbfd3', per the official
  // Kurier docs), while the platform's proof_tx is a 0x-hex hash
  // (event-page sample '0xa4c1...8ff1'). Every valid task therefore
  // fail-closed to REJECT/PROOF_NOT_CONFIRMED (-3 each). The event rules
  // define only the 7 field checks; the platform itself re-verifies the
  // Groth16 decision proof we return. Kurier confirmation is therefore
  // advisory-only and must NOT gate the decision.
  log(taskId, 'all field checks pass — approving (Kurier confirm removed: proof_tx is not a Kurier jobId)');

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
    // Fire-and-forget: do not block the 60s response on Kurier finalization.
    kurier.submitProof({ proof: proofRes.proof, publicSignals: proofRes.publicSignals, vkHash: VK_HASH })
      .then((r) => log(taskId, `kurier submit-proof: ${r.jobId ? 'jobId ' + r.jobId : 'error ' + r.error}`))
      .catch((e) => log(taskId, `kurier submit-proof threw: ${e.message}`));
  }

  // 6. APPROVE: record the proof_tx so a replay is caught as PROOF_REUSED.
  seen.add(proofTx);

  const body = { decision: 'APPROVE', reason_code: REASONS.VALID, proof_tx: proofTx };
  if (proofRes.available) {
    body.proof = proofRes.proof;
    body.publicSignals = proofRes.publicSignals;
    body.vkHash = VK_HASH;
  }
  return { status: 200, body, taskId, logMsg: `APPROVE/VALID_CONDITION in ${Date.now() - started}ms${proofRes.available ? ' + local proof' : ' (no local proof)'}` };
}

const server = http.createServer((req, res) => {
  const url = req.url || '/';
  if (req.method === 'GET' && (url === '/health' || url === '/healthz')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', seen: seen.size(), kurier: kurier.configured() }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const rawBody = Buffer.concat(chunks);
    try {
      const { status, body, taskId, logMsg } = await handleTask(rawBody, req);
      log(taskId, logMsg);
      sendSigned(res, status, body);
    } catch (e) {
      console.error('[error] handleTask threw:', e);
      // Fail closed even on an unexpected error.
      sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.UNCONFIRMED, proof_tx: '' });
    }
  });
  req.on('error', (e) => {
    console.error('[error] request error:', e.message);
    try { sendSigned(res, 400, { error: 'bad request' }); } catch { /* socket gone */ }
  });
});

server.listen(PORT, () => {
  console.log(`[boot] proof-gatekeeper agent listening on :${PORT} (health: GET /health)`);
});
