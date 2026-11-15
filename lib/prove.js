// prove.js — local Groth16 decision-proof generation (snarkjs + gatekeeper circuit).
//
// Circuit inputs (13, all public — discovered by probing the WASM):
//   taskId, decision, minimum, publicBalance, expiryBlock, currentBlock,
//   recipient, conditionRecipient, amount, maxTransfer,
//   registeredVkHash, proofVkHash, salt
//
// Encoding (best effort, verified empirically against the circuit by
// `verifyLocally` — see prove.test.js):
//   - taskId:            keccak256(task_id string) as a field element
//   - decision:          1 = APPROVE, 0 = REJECT
//   - minimum/publicBalance/amount/maxTransfer/expiryBlock/currentBlock:
//                        the integer values from the task
//   - recipient/conditionRecipient: the address parsed as a field element
//   - registeredVkHash / proofVkHash: the VK hex value parsed as a field element
//                        (the VKs are already hashes; the circuit takes the hash value)
//   - salt:              a fresh random field element per proof
//
// The circuit constrains: decision is 0/1, and APPROVE (1) requires
// registeredVkHash == proofVkHash, publicBalance >= minimum,
// currentBlock <= expiryBlock, recipient == conditionRecipient and
// amount <= maxTransfer. A proof generated from a task that violates those
// constraints will NOT verify — which is exactly the point: the proof is only
// valid when the decision is consistent with the task.
//
// If the encoding ever fails local verification, generateProof() returns
// { available: false, reason } and the server responds with the decision but
// NO proof (the platform scores that as a correct decision minus the proof
// bonus/penalty — it never fakes a proof).

const fs = require('fs');
const crypto = require('crypto');
const { keccak256 } = require('js-sha3');

const BN128_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

function fieldElem(hexOrBig) {
  let v;
  if (typeof hexOrBig === 'bigint') v = hexOrBig;
  else if (typeof hexOrBig === 'number') v = BigInt(hexOrBig);
  else {
    const s = String(hexOrBig).trim();
    v = s.startsWith('0x') || s.startsWith('0X') ? BigInt(s) : BigInt(s);
  }
  // Reduce into the field (addresses / hashes already fit, but be safe).
  return ((v % BN128_PRIME) + BN128_PRIME) % BN128_PRIME;
}

function keccakField(str) {
  const h = keccak256(str);
  return fieldElem('0x' + h);
}

function randomSalt() {
  // 31 random bytes -> a field element (always < prime since 31 bytes < 32).
  return fieldElem('0x' + crypto.randomBytes(31).toString('hex'));
}

// Build the circuit input object from a task input + decision.
// `opts.taskIdMode` can be 'keccak' (default) or 'numeric'.
// `opts.vkMode` can be 'raw' (default: VK hex as field element) or 'keccak'.
function buildInput(input, decision, opts = {}) {
  const taskIdMode = opts.taskIdMode || 'keccak';
  const vkMode = opts.vkMode || 'raw';
  let taskId;
  if (taskIdMode === 'keccak') taskId = keccakField(String(input.task_id || ''));
  else if (taskIdMode === 'numeric') taskId = fieldElem(String(input.task_id || '0').replace(/[^0-9]/g, '') || '0');
  else throw new Error(`unknown taskIdMode ${taskIdMode}`);

  const vkHash = (vk) => {
    if (vkMode === 'raw') return fieldElem(vk);
    if (vkMode === 'keccak') return keccakField(String(vk).toLowerCase());
    throw new Error(`unknown vkMode ${vkMode}`);
  };

  return {
    taskId: taskId.toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
    minimum: BigInt(String(input.minimum)).toString(),
    publicBalance: BigInt(String(input.public_balance)).toString(),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: fieldElem(input.recipient).toString(),
    conditionRecipient: fieldElem(input.condition_recipient).toString(),
    amount: BigInt(String(input.amount)).toString(),
    maxTransfer: BigInt(String(input.max_transfer)).toString(),
    registeredVkHash: vkHash(input.registered_vk).toString(),
    proofVkHash: vkHash(input.proof_vk).toString(),
    salt: randomSalt().toString(),
  };
}

let _vk = null;
async function getVk(zkeyPath) {
  if (_vk) return _vk;
  const snarkjs = require('snarkjs');
  _vk = await snarkjs.zKey.exportVerificationKey(zkeyPath);
  return _vk;
}

// Generate a Groth16 proof for a decision. Returns:
//   { available: true, proof, publicSignals, vkHash, input }
// or { available: false, reason }.
// `verify` (default true) re-verifies the proof locally against the VK
// before returning it — a proof that does not verify locally is never sent.
async function generateProof({ input, decision, wasmPath, zkeyPath, opts = {}, verify = true }) {
  let snarkjs;
  try {
    snarkjs = require('snarkjs');
  } catch (e) {
    return { available: false, reason: 'snarkjs not installed' };
  }
  if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
    return { available: false, reason: 'circuit artifacts missing' };
  }
  const circuitInput = buildInput(input, decision, opts);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInput,
      wasmPath,
      zkeyPath
    );
    if (verify) {
      const vk = await getVk(zkeyPath);
      const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
      if (!ok) {
        return { available: false, reason: 'local verification failed (encoding mismatch?)', input: circuitInput, publicSignals };
      }
    }
    return { available: true, proof, publicSignals, input: circuitInput };
  } catch (e) {
    return { available: false, reason: `proof generation error: ${e.message}`, input: circuitInput };
  }
}

module.exports = { buildInput, generateProof, getVk, keccakField, fieldElem, randomSalt };
