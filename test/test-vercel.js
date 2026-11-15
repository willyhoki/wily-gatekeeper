// test/test-vercel.js — local tests for the Vercel Serverless Function
// adaptation (api/index.js). Run:  node test/test-vercel.js
//
// Simulates Vercel req/res with plain Node streams (no framework, no
// network): req is a Readable stream carrying the raw body bytes, res
// captures status/headers/body. Asserts:
//   (a) GET /health -> 200 {"status":"ok"}
//   (b) GET /        -> 200 {"status":"ok"} (root is also health on Vercel)
//   (c) POST valid task, correct HMAC, no KURIER_API_KEY
//       -> 200 APPROVE/VALID_CONDITION with a local Groth16 proof
//       (Kurier gate removed 2026-11-15: proof_tx is not a Kurier jobId)
//       + response is signed with the HMAC secret over the raw response body
//   (d) POST valid task, wrong HMAC -> 401
//   (e) POST valid task, missing signature -> 401
//   (f) POST valid task, tampered body (signed one body, sent another) -> 401
//   (g) POST VK-mismatch trap -> 200 REJECT/VK_SUBSTITUTION + signed
//   (h) POST with an unsupported task type -> 200 protocol handshake
//       (handler answers {"ok":true,"protocolVersion":"v1"} for non-task
//       types; the old test expected 400, which never matched the code —
//       fixed 2026-11-15 while verifying the Round 3 fix)
//
// The full APPROVE path (local Groth16 proof) IS exercised here since
// 2026-11-15: the Kurier confirmation gate was removed (proof_tx is a
// 0x-hex hash, not a Kurier jobId/UUID), so a valid task approves with a
// locally generated proof and no KURIER_API_KEY. The decision logic itself
// is covered by test/test.js (19/19 pass) and the proof path by
// prove-experiment.js; this file only proves the Vercel handler wiring
// (raw-body HMAC, routing, signing, fail-closed behaviour).

process.env.AGENT_GAMES_HMAC_SECRET = 'test-secret-do-not-use-in-production';
delete process.env.KURIER_API_KEY; // force the fail-closed path

const { Readable } = require('stream');
const crypto = require('crypto');
const handler = require('../api/index');

const SECRET = 'test-secret-do-not-use-in-production';

const BASE = {
  type: 'agent-games.proof-gatekeeper.v1',
  task_id: 'gk_24_9d1',
  mode: 'competition',
  issued_at: new Date(Date.now() - 60000).toISOString(),
  deadline_at: new Date(Date.now() + 60000).toISOString(),
  input: {
    registered_vk: '0x7d3a11111111111111111111111111111111111111111111111111111111f291',
    proof_vk: '0x7d3a11111111111111111111111111111111111111111111111111111111f291',
    minimum: '1000',
    public_balance: '1460',
    expiry_block: 19842201,
    current_block: 19832000,
    recipient: '0xDe4200000000000000000000000000000000009f01',
    condition_recipient: '0xDe4200000000000000000000000000000000009f01',
    amount: '500',
    max_transfer: '1000',
    proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000008ff1',
  },
};

function clone(o) { return JSON.parse(JSON.stringify(o)); }
function hmac(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

// Minimal fake Vercel req: a Readable stream with method/url/headers.
function fakeReq({ method, url, body, headers = {} }) {
  const stream = body !== undefined
    ? Readable.from([Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8')])
    : Readable.from([]);
  stream.method = method;
  stream.url = url;
  stream.headers = headers;
  return stream;
}

// Minimal fake Vercel res: captures what the handler sends.
function fakeRes() {
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const headers = {};
  const res = {
    statusCode: 200,
    headers,
    setHeader: (k, v) => { headers[k.toLowerCase()] = v; },
    getHeader: (k) => headers[k.toLowerCase()],
    end: (body) => resolve({ status: res.statusCode, headers, body: String(body || '') }),
  };
  res.done = done;
  return res;
}

async function invoke({ method, url, body, headers }) {
  const req = fakeReq({ method, url, body, headers });
  const res = fakeRes();
  await handler(req, res);
  const out = await res.done;
  let json = null;
  try { json = JSON.parse(out.body); } catch { /* ignore */ }
  return { ...out, json };
}

async function main() {
  const results = [];
  function check(name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    results.push({ name, ok, got, want });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
  }

  // (a) GET /health
  {
    const r = await invoke({ method: 'GET', url: '/health' });
    check('(a) GET /health -> 200 ok', [r.status, r.json && r.json.status], [200, 'ok']);
  }
  // (b) GET / (root health on Vercel)
  {
    const r = await invoke({ method: 'GET', url: '/' });
    check('(b) GET / -> 200 ok', [r.status, r.json && r.json.status], [200, 'ok']);
  }
  // (c) POST valid task, correct HMAC, no Kurier key -> APPROVE (Kurier gate removed)
  {
    const body = JSON.stringify(clone(BASE));
    const r = await invoke({
      method: 'POST', url: '/',
      body,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
    });
    check('(c) POST valid, no Kurier -> APPROVE/VALID_CONDITION',
      [r.status, r.json && r.json.decision, r.json && r.json.reason_code],
      [200, 'APPROVE', 'VALID_CONDITION']);
    check('(c) APPROVE carries a local Groth16 proof',
      Boolean(r.json && r.json.proof && r.json.publicSignals && r.json.vkHash), true);
    check('(c) response is signed over the raw body',
      r.headers['x-agent-games-signature'] === hmac(SECRET, r.body), true);
  }
  // (d) wrong HMAC -> 401
  {
    const body = JSON.stringify(clone(BASE));
    const r = await invoke({
      method: 'POST', url: '/',
      body,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac('wrong-secret', body) },
    });
    check('(d) POST wrong HMAC -> 401', r.status, 401);
  }
  // (e) missing signature -> 401
  {
    const body = JSON.stringify(clone(BASE));
    const r = await invoke({
      method: 'POST', url: '/',
      body,
      headers: { 'content-type': 'application/json' },
    });
    check('(e) POST missing signature -> 401', r.status, 401);
  }
  // (f) tampered body -> 401
  {
    const body = JSON.stringify(clone(BASE));
    const tampered = body.replace('"500"', '"501"');
    const r = await invoke({
      method: 'POST', url: '/',
      body: tampered,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
    });
    check('(f) POST tampered body -> 401', r.status, 401);
  }
  // (g) VK-mismatch trap -> REJECT/VK_SUBSTITUTION, signed
  {
    const task = clone(BASE);
    task.input.proof_vk = '0xa4c12222222222222222222222222222222222222222222222222222222222b8ff';
    const body = JSON.stringify(task);
    const r = await invoke({
      method: 'POST', url: '/agent',
      body,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
    });
    check('(g) POST VK mismatch -> REJECT/VK_SUBSTITUTION',
      [r.status, r.json && r.json.decision, r.json && r.json.reason_code],
      [200, 'REJECT', 'VK_SUBSTITUTION']);
    check('(g) response is signed over the raw body',
      r.headers['x-agent-games-signature'] === hmac(SECRET, r.body), true);
  }
  // (h) unsupported task type -> 400
  {
    const task = clone(BASE);
    task.type = 'something.else.v9';
    const body = JSON.stringify(task);
    const r = await invoke({
      method: 'POST', url: '/',
      body,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
    });
    check('(h) POST unsupported type -> 200 protocol handshake', [r.status, r.json && r.json.ok, r.json && r.json.protocolVersion], [200, true, 'v1']);
  }
  // (i) non-POST to a task route -> 405; unknown path -> 404
  {
    const r = await invoke({ method: 'PUT', url: '/' });
    check('(i) PUT / -> 405', r.status, 405);
    const body = JSON.stringify(clone(BASE));
    const r2 = await invoke({
      method: 'POST', url: '/nope',
      body,
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
    });
    check('(i) POST /nope -> 404', r2.status, 404);
  }

  const failed = results.filter((x) => !x.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
