// decide.js — the deterministic Proof Gatekeeper decision logic.
// Pure function: given a task input + a seen-set, return {decision, reason_code}.
// Check order follows the Agent Games trap encyclopedia and the event page:
//   1. VK_SUBSTITUTION   proof_vk != registered_vk
//   2. THRESHOLD_MISMATCH public_balance < minimum
//   3. PROOF_REUSED       proof_tx already in the seen-set
//   4. EXPIRED_CONDITION  current_block > expiry_block
//   5. RECIPIENT_MISMATCH recipient != condition_recipient
//   6. AMOUNT_OVERFLOW    amount > max_transfer
//   7. otherwise          VALID_CONDITION -> APPROVE
//
// IMPORTANT: this function does NOT decide proof confirmation. The caller
// (server.js) gates an APPROVE on independent proof confirmation and fails
// closed (REJECT) when the proof cannot be confirmed. decide() only answers
// "do the fields describe a valid condition?".
//
// reason_code PROOF_NOT_CONFIRMED is NOT one of the 7 documented codes; it is
// used only by server.js when every field check passes but the incoming proof
// could not be independently confirmed. It is never used to approve anything.

const REASONS = {
  VALID: 'VALID_CONDITION',
  VK: 'VK_SUBSTITUTION',
  THRESHOLD: 'THRESHOLD_MISMATCH',
  REUSED: 'PROOF_REUSED',
  EXPIRED: 'EXPIRED_CONDITION',
  RECIPIENT: 'RECIPIENT_MISMATCH',
  AMOUNT: 'AMOUNT_OVERFLOW',
  UNCONFIRMED: 'PROOF_NOT_CONFIRMED',
};

function normAddr(a) {
  return String(a == null ? '' : a).trim().toLowerCase();
}
function normHex(h) {
  return String(h == null ? '' : h).trim().toLowerCase();
}
function toBig(v, name) {
  try {
    if (v == null || v === '') throw new Error('missing');
    return BigInt(String(v).trim());
  } catch {
    throw new Error(`field ${name} is not a valid integer: ${JSON.stringify(v)}`);
  }
}
function toNum(v, name) {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`field ${name} is not a valid number: ${JSON.stringify(v)}`);
  return n;
}

// input: the task's `input` object. seen: object with has(tx) / add(tx).
// Returns { decision: 'APPROVE'|'REJECT', reason_code, detail }.
// Throws on malformed input (caller turns that into a fail-closed REJECT).
function decide(input, seen) {
  if (!input || typeof input !== 'object') throw new Error('task input missing');

  const registeredVk = normHex(input.registered_vk);
  const proofVk = normHex(input.proof_vk);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const proofTx = normHex(input.proof_tx);

  if (!registeredVk || !proofVk) throw new Error('missing verification key');
  if (!proofTx) throw new Error('missing proof_tx');
  if (!recipient || !conditionRecipient) throw new Error('missing recipient');

  const minimum = toBig(input.minimum, 'minimum');
  const publicBalance = toBig(input.public_balance, 'public_balance');
  const amount = toBig(input.amount, 'amount');
  const maxTransfer = toBig(input.max_transfer, 'max_transfer');
  const expiryBlock = toNum(input.expiry_block, 'expiry_block');
  const currentBlock = toNum(input.current_block, 'current_block');

  // 1. Verification-key substitution.
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: REASONS.VK, detail: 'proof_vk != registered_vk' };
  }
  // 2. Threshold mismatch.
  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: REASONS.THRESHOLD, detail: `public_balance ${publicBalance} < minimum ${minimum}` };
  }
  // 3. Proof reused (seen-set). Do NOT re-add; the caller adds only on APPROVE.
  if (seen.has(proofTx)) {
    return { decision: 'REJECT', reason_code: REASONS.REUSED, detail: 'proof_tx already seen' };
  }
  // 4. Expired condition.
  if (currentBlock > expiryBlock) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED, detail: `current_block ${currentBlock} > expiry_block ${expiryBlock}` };
  }
  // 5. Recipient mismatch.
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: REASONS.RECIPIENT, detail: 'recipient != condition_recipient' };
  }
  // 6. Amount overflow.
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: REASONS.AMOUNT, detail: `amount ${amount} > max_transfer ${maxTransfer}` };
  }
  // 7. Valid condition.
  return { decision: 'APPROVE', reason_code: REASONS.VALID, detail: 'all field checks pass' };
}

module.exports = { decide, REASONS };
