// seen.js — persistent seen-set of proof_tx values (PROOF_REUSED detection).
// Stored as a JSON array on disk so reuse detection survives restarts.
const fs = require('fs');
const path = require('path');

function loadSeen(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return new Set(arr.map(String));
  } catch (e) {
    if (e.code !== 'ENOENT') console.error('[seen] load error:', e.message);
  }
  return new Set();
}

function saveSeen(filePath, set) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify([...set].sort(), null, 2), 'utf8');
  fs.renameSync(tmp, filePath);
}

function createSeenStore(filePath) {
  let set = loadSeen(filePath);
  return {
    has: (tx) => set.has(String(tx)),
    add: (tx) => {
      set.add(String(tx));
      saveSeen(filePath, set);
    },
    size: () => set.size,
    // For tests / reset only.
    clear: () => {
      set = new Set();
      saveSeen(filePath, set);
    },
  };
}

module.exports = { createSeenStore };
