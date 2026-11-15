// test/test.js — decision-logic + HTTP integration tests for the Gatekeeper agent.
// Run:  node test/test.js
// Spawns server.js as a child (test HMAC secret, ALLOW_UNSIGNED unset,
// no KURIER_API_KEY) and POSTs the sample payload + one mutated variant per
// trap type. Prints PASS/FAIL per case and exits non-zero on any failure.
//
// NOTE on the VALID case: since 2026-11-15 (Round 3 fix) the agent no
// longer gates APPROVE on Kurier confirmation — proof_tx is a 0x-hex hash,
// not a Kurier jobId (UUID), so that lookup could never succeed. A valid
// task now APPROVEs with a locally generated + verified Groth16 proof.

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 3456;
const SECRET = 'test-secret-do-not-use-in-production';
const SEEN_FILE = path.join(__dirname, 'seen-test.json');
const SERVER = path.join(__dirname, '..', 'server.js');

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

async function postTask(task, { sign = true, secret = SECRET } = {}) {
  const body = JSON.stringify(task);
  const headers = { 'content-type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmac(secret, body);
  const res = await fetch(`http://127.0.0.1:${PORT}/`, { method: 'POST', headers, body });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* ignore */ }
  return { status: res.status, json, text, sig: res.headers.get('x-agent-games-signature') };
}

async function main() {
  // Pre-seed the seen-set with one proof_tx for the PROOF_REUSED case.
  const reusedTx = '0xbeef00000000000000000000000000000000000000000000000000000000beef';
  fs.mkdirSync(path.dirname(SEEN_FILE), { recursive: true });
  fs.writeFileSync(SEEN_FILE, JSON.stringify([reusedTx]), 'utf8');

  const child = spawn(process.execPath, [SERVER], {
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_FILE,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  child.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));

  // Wait for the health endpoint.
  let up = false;
  for (let i = 0; i < 30 && !up; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/health`);
      if (r.ok) up = true;
    } catch { /* not up yet */ }
    if (!up) await new Promise((r) => setTimeout(r, 500));
  }
  if (!up) { console.error('FATAL: server did not come up'); child.kill(); process.exit(2); }

  const results = [];
  function check(name, got, want) {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    results.push({ name, ok, got, want });
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
  }

  // --- 1. Pure decision logic (decide() directly, no Kurier gate) ---
  const { decide } = require('../lib/decide');
  const seenForUnit = { has: () => false, add: () => {} };
  check('unit: valid fields -> APPROVE/VALID_CONDITION',
    ((v) => [v.decision, v.reason_code])(decide(clone(BASE).input, seenForUnit)),
    ['APPROVE', 'VALID_CONDITION']);

  const cases = [
    ['http: sample payload (VK mismatch in the event page sample) -> REJECT/VK_SUBSTITUTION',
      (() => { const t = clone(BASE); t.input.proof_vk = '0xa4c12222222222222222222222222222222222222222222222222222222222b8ff'; return t; })(),
      ['REJECT', 'VK_SUBSTITUTION']],
    ['http: threshold mismatch (balance 500 < min 1000) -> REJECT/THRESHOLD_MISMATCH',
      (() => { const t = clone(BASE); t.input.public_balance = '500'; return t; })(),
      ['REJECT', 'THRESHOLD_MISMATCH']],
    ['http: proof reused (proof_tx pre-seeded) -> REJECT/PROOF_REUSED',
      (() => { const t = clone(BASE); t.input.proof_tx = reusedTx; return t; })(),
      ['REJECT', 'PROOF_REUSED']],
    ['http: expired condition (current 19843000 > expiry 19842201) -> REJECT/EXPIRED_CONDITION',
      (() => { const t = clone(BASE); t.input.current_block = 19843000; return t; })(),
      ['REJECT', 'EXPIRED_CONDITION']],
    ['http: recipient mismatch -> REJECT/RECIPIENT_MISMATCH',
      (() => { const t = clone(BASE); t.input.recipient = '0x1111000000000000000000000000000000000001'; return t; })(),
      ['REJECT', 'RECIPIENT_MISMATCH']],
    ['http: amount overflow (1500 > max 1000) -> REJECT/AMOUNT_OVERFLOW',
      (() => { const t = clone(BASE); t.input.amount = '1500'; return t; })(),
      ['REJECT', 'AMOUNT_OVERFLOW']],
    ['http: valid fields -> APPROVE/VALID_CONDITION (Kurier gate removed 2026-11-15)',
      clone(BASE),
      ['APPROVE', 'VALID_CONDITION']],
  ];

  for (const [name, task, want] of cases) {
    const r = await postTask(task);
    check(name, [r.json && r.json.decision, r.json && r.json.reason_code], want);
    // Response must be signed.
    const expectedSig = hmac(SECRET, JSON.stringify(r.json));
    check(name + ' [response signed]', r.sig === expectedSig, true);
  }

  // --- HMAC failures ---
  let r = await postTask(clone(BASE), { sign: false });
  check('http: missing signature -> 401', r.status, 401);
  r = await postTask(clone(BASE), { sign: true, secret: 'wrong-secret' });
  check('http: wrong signature -> 401', r.status, 401);
  // Tampered body: sign one body, send another.
  {
    const body = JSON.stringify(clone(BASE));
    const tampered = body.replace('"500"', '"501"');
    const res = await fetch(`http://127.0.0.1:${PORT}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-agent-games-signature': hmac(SECRET, body) },
      body: tampered,
    });
    check('http: tampered body -> 401', res.status, 401);
  }

  // --- Health ---
  {
    const res = await fetch(`http://127.0.0.1:${PORT}/health`);
    const j = await res.json();
    check('http: GET /health -> 200 ok', [res.status, j.status], [200, 'ok']);
  }

  const failed = results.filter((x) => !x.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  child.kill();
  try { fs.unlinkSync(SEEN_FILE); } catch { /* ignore */ }
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error('FATAL', e); process.exit(2); });
