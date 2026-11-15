// kurier.js — Kurier REST client (zkVerify proof verification, mainnet).
// Docs: https://docs.zkverify.io/overview/getting-started/kurier
//   Mainnet API: https://api.kurier.xyz/api/v1
//   POST /register-vk/{API_KEY}   {proofType, vk, proofOptions}
//   POST /submit-proof/{API_KEY}  {proofType, vkRegistered, proofOptions, proofData:{proof, publicSignals, vk}}
//   GET  /job-status/{API_KEY}/{jobId}
// Status flow: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized | Failed
//
// Two uses here:
//   1. confirmProof(proofTx): ask Kurier whether the incoming proof reference
//      (proof_tx) is a known, finalized verification job. This is a
//      best-effort confirmation; a 404/unknown reference means "not confirmed"
//      and the caller fails closed.
//   2. submitProof(proof, publicSignals, vkHash): submit the agent's own
//      locally-generated Groth16 decision proof for on-chain verification and
//      poll job-status until Finalized (bounded wait; the HTTP response to the
//      platform is NOT blocked on this — it is fire-and-forget with logging,
//      because Kurier finalization can exceed the 60s task deadline).

const DEFAULT_API_URL = 'https://api.kurier.xyz/api/v1';
const FINAL_STATES = new Set(['Finalized', 'IncludedInBlock', 'Submitted', 'Valid']);
const CONFIRMED_STATES = new Set(['Finalized', 'IncludedInBlock']);

function apiUrl() {
  return (process.env.KURIER_API_URL || DEFAULT_API_URL).replace(/\/+$/, '');
}
function apiKey() {
  return process.env.KURIER_API_KEY || '';
}
function configured() {
  return Boolean(apiKey());
}

async function getJson(url, timeoutMs = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, body, text };
  } finally {
    clearTimeout(t);
  }
}

async function postJson(url, payload, timeoutMs = 30000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, body, text };
  } finally {
    clearTimeout(t);
  }
}

// Confirm the incoming proof reference. Returns
// { confirmed: boolean, status: string|null, detail: string }.
// confirmed=true only when Kurier reports a Finalized/IncludedInBlock job.
// Anything else (no key, 404, network error, non-final state) => not confirmed.
async function confirmProof(proofTx) {
  if (!configured()) {
    return { confirmed: false, status: null, detail: 'KURIER_API_KEY not configured' };
  }
  const ref = encodeURIComponent(String(proofTx));
  try {
    const r = await getJson(`${apiUrl()}/job-status/${apiKey()}/${ref}`, 15000);
    if (!r.ok || !r.body) {
      return { confirmed: false, status: null, detail: `kurier job-status HTTP ${r.status}` };
    }
    const status = r.body.status || r.body.state || null;
    const txHash = r.body.txHash || r.body.tx_hash || null;
    return {
      confirmed: CONFIRMED_STATES.has(status),
      status,
      txHash,
      detail: `kurier job-status=${status}`,
    };
  } catch (e) {
    return { confirmed: false, status: null, detail: `kurier confirmProof error: ${e.message}` };
  }
}

// Register the gatekeeper verification key once (idempotent; an already
// registered VK returns its existing vkHash). Returns { vkHash } or { error }.
async function registerVk(vk, vkHash) {
  if (!configured()) return { error: 'KURIER_API_KEY not configured' };
  const payload = {
    proofType: 'groth16',
    vk,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
  };
  try {
    const r = await postJson(`${apiUrl()}/register-vk/${apiKey()}`, payload, 30000);
    if (!r.ok) return { error: `register-vk HTTP ${r.status}: ${String(r.text || '').slice(0, 200)}` };
    const hash = (r.body && (r.body.vkHash || r.body.uniq_vk_hash || r.body.vk_hash)) || vkHash || null;
    return { vkHash: hash, raw: r.body };
  } catch (e) {
    return { error: `register-vk error: ${e.message}` };
  }
}

// Submit the agent's own Groth16 proof. Returns { jobId } or { error }.
async function submitProof({ proof, publicSignals, vkHash }) {
  if (!configured()) return { error: 'KURIER_API_KEY not configured' };
  const payload = {
    proofType: 'groth16',
    vkRegistered: true,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: { proof, publicSignals, vk: vkHash },
  };
  try {
    const r = await postJson(`${apiUrl()}/submit-proof/${apiKey()}`, payload, 30000);
    if (!r.ok) return { error: `submit-proof HTTP ${r.status}: ${String(r.text || '').slice(0, 200)}` };
    const jobId = r.body && (r.body.jobId || r.body.job_id || r.body.id);
    return { jobId: jobId || null, raw: r.body };
  } catch (e) {
    return { error: `submit-proof error: ${e.message}` };
  }
}

// Poll job-status until Finalized/Failed or the deadline. Returns the last
// status object. Bounded so it never blocks a task response indefinitely.
async function pollJob(jobId, { intervalMs = 5000, timeoutMs = 120000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const r = await getJson(`${apiUrl()}/job-status/${apiKey()}/${encodeURIComponent(jobId)}`, 15000);
      last = r.body || { status: `HTTP ${r.status}` };
      const status = last.status || last.state;
      if (status === 'Finalized' || status === 'Failed') return last;
    } catch (e) {
      last = { status: 'poll-error', error: e.message };
    }
    await new Promise((res) => setTimeout(res, intervalMs));
  }
  return last || { status: 'poll-timeout' };
}

module.exports = {
  configured,
  confirmProof,
  registerVk,
  submitProof,
  pollJob,
  FINAL_STATES,
  CONFIRMED_STATES,
};
