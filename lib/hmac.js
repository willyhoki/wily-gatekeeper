// hmac.js — HMAC-SHA256 helpers for Agent Games.
// Incoming: verify the signature over the RAW request body BEFORE parsing.
// Outgoing: sign the raw response body with x-agent-games-signature.
const crypto = require('crypto');

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

// Accepts "hex", "sha256=hex", or base64. Returns true only on an exact,
// timing-safe match. Missing/empty signature or secret => false (fail closed).
function verifyHmac(secret, rawBody, signatureHeader) {
  if (!secret || !signatureHeader) return false;
  let sig = String(signatureHeader).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const expectedHex = hmacHex(secret, rawBody);
  let sigBuf;
  try {
    // Signature is hex in the platform's convention; tolerate base64 too.
    sigBuf = /^[0-9a-fA-F]+$/.test(sig) && sig.length % 2 === 0
      ? Buffer.from(sig, 'hex')
      : Buffer.from(sig, 'base64');
  } catch {
    return false;
  }
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (sigBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(sigBuf, expectedBuf);
}

function signBody(secret, rawBody) {
  return hmacHex(secret, rawBody);
}

module.exports = { hmacHex, verifyHmac, signBody };
