/**
 * VLI AI Trust Protocol — Proof Chain Engine
 *
 * Every AI event is:
 * 1. Canonicalized (deterministic JSON, sorted keys)
 * 2. Hashed (SHA-256)
 * 3. Chain-linked (hash of previous + current)
 * 4. Signed (Ed25519)
 * 5. Stored (SQLite)
 * 6. Optionally anchored (Merkle root → VLI Registry)
 */
import { sha256, canonicalize, signData, verifySignature, randomId, buildMerkleRoot } from "./crypto.js";
import { getDb, getKeys } from "./store.js";

/**
 * Seal an event into the proof chain.
 *
 * @param {string} sessionId
 * @param {string} eventType — e.g. 'ai.decision', 'ai.access', 'ai.checkpoint'
 * @param {object} payload — the data being sealed
 * @returns {{ event_id, payload_hash, chain_hash, signature, seq }}
 */
export function sealEvent(sessionId, eventType, payload) {
  const db = getDb();
  const keys = getKeys();
  const now = new Date().toISOString();

  // Canonicalize and hash the payload
  const canonical = canonicalize(payload);
  const payloadHash = sha256(canonical);

  // Get previous event in this session for chain linking
  const prev = db.prepare(
    "SELECT chain_hash, seq FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT 1"
  ).get(sessionId);

  const prevHash = prev ? prev.chain_hash : sha256("genesis:" + sessionId);
  const seq = prev ? prev.seq + 1 : 0;

  // Chain hash = hash(prevHash + payloadHash)
  const chainHash = sha256(prevHash + ":" + payloadHash);

  // Sign the chain hash
  const signature = signData(chainHash, keys.privateKey);

  // Store
  const eventId = randomId("ait");
  db.prepare(`
    INSERT INTO events (event_id, session_id, event_type, seq, payload_json, payload_hash, prev_hash, chain_hash, signature, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(eventId, sessionId, eventType, seq, canonical, payloadHash, prevHash, chainHash, signature, now);

  // Update session event count
  db.prepare("UPDATE sessions SET event_count = event_count + 1 WHERE session_id = ?").run(sessionId);

  return { event_id: eventId, payload_hash: payloadHash, chain_hash: chainHash, signature, seq };
}

/**
 * Verify the integrity of a session's proof chain.
 *
 * @param {string} sessionId
 * @returns {{ valid, events_checked, errors }}
 */
export function verifyChain(sessionId) {
  const db = getDb();
  const keys = getKeys();
  const events = db.prepare(
    "SELECT * FROM events WHERE session_id = ? ORDER BY seq ASC"
  ).all(sessionId);

  const errors = [];
  let expectedPrev = sha256("genesis:" + sessionId);

  for (const evt of events) {
    // Verify payload hash
    const computedPayloadHash = sha256(evt.payload_json);
    if (computedPayloadHash !== evt.payload_hash) {
      errors.push({ event_id: evt.event_id, error: "payload_hash mismatch", expected: computedPayloadHash, got: evt.payload_hash });
    }

    // Verify chain link
    const computedChainHash = sha256(expectedPrev + ":" + evt.payload_hash);
    if (computedChainHash !== evt.chain_hash) {
      errors.push({ event_id: evt.event_id, error: "chain_hash mismatch", expected: computedChainHash, got: evt.chain_hash });
    }

    // Verify signature
    if (!verifySignature(evt.chain_hash, evt.signature, keys.publicKey)) {
      errors.push({ event_id: evt.event_id, error: "signature invalid" });
    }

    expectedPrev = evt.chain_hash;
  }

  return {
    valid: errors.length === 0,
    events_checked: events.length,
    errors,
    public_key: keys.publicKey,
  };
}

/**
 * Verify a single event.
 *
 * @param {string} eventId
 * @returns {object}
 */
export function verifyEvent(eventId) {
  const db = getDb();
  const keys = getKeys();
  const evt = db.prepare("SELECT * FROM events WHERE event_id = ?").get(eventId);
  if (!evt) return { valid: false, error: "Event not found" };

  const computedPayloadHash = sha256(evt.payload_json);
  const payloadValid = computedPayloadHash === evt.payload_hash;
  const signatureValid = verifySignature(evt.chain_hash, evt.signature, keys.publicKey);

  let payload;
  try { payload = JSON.parse(evt.payload_json); } catch { payload = null; }

  return {
    valid: payloadValid && signatureValid,
    event_id: evt.event_id,
    session_id: evt.session_id,
    event_type: evt.event_type,
    seq: evt.seq,
    payload_hash: evt.payload_hash,
    chain_hash: evt.chain_hash,
    signature: evt.signature,
    payload_valid: payloadValid,
    signature_valid: signatureValid,
    public_key: keys.publicKey,
    created_at: evt.created_at,
    payload,
  };
}

/**
 * Create a Merkle batch anchor from un-anchored events.
 *
 * @returns {{ batch_id, event_count, merkle_root } | null}
 */
export function createAnchorBatch() {
  const db = getDb();

  // Ensure mapping table exists
  db.exec(`CREATE TABLE IF NOT EXISTS anchor_event_map (
    event_id TEXT NOT NULL, batch_id TEXT NOT NULL,
    PRIMARY KEY (event_id, batch_id)
  )`);

  const events = db.prepare(
    "SELECT event_id, chain_hash FROM events WHERE event_id NOT IN (SELECT event_id FROM anchor_event_map) ORDER BY created_at ASC"
  ).all();

  if (events.length === 0) return null;

  const leaves = events.map(e => e.chain_hash);
  const merkleRoot = buildMerkleRoot(leaves);
  const batchId = randomId("batch");
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO anchors (batch_id, event_count, merkle_root, status, created_at)
    VALUES (?, ?, ?, 'pending', ?)
  `).run(batchId, events.length, merkleRoot, now);

  const insert = db.prepare("INSERT INTO anchor_event_map (event_id, batch_id) VALUES (?, ?)");
  for (const evt of events) {
    insert.run(evt.event_id, batchId);
  }

  return { batch_id: batchId, event_count: events.length, merkle_root: merkleRoot };
}

/**
 * Submit anchor batch to VLI Registry.
 *
 * @param {string} batchId
 * @param {string} registryUrl
 * @returns {object}
 */
export async function submitAnchor(batchId, registryUrl) {
  const db = getDb();
  const batch = db.prepare("SELECT * FROM anchors WHERE batch_id = ?").get(batchId);
  if (!batch) throw new Error("Batch not found");

  try {
    const res = await fetch(registryUrl + "/api/anchor", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        batch_id: batch.batch_id,
        merkle_root: batch.merkle_root,
        event_count: batch.event_count,
        source: "mcp-ai-trust",
      }),
    });

    if (!res.ok) throw new Error("Registry returned " + res.status);
    const data = await res.json();

    db.prepare(
      "UPDATE anchors SET status = 'anchored', registry_ref = ?, anchored_at = ? WHERE batch_id = ?"
    ).run(JSON.stringify(data), new Date().toISOString(), batchId);

    return { status: "anchored", batch_id: batchId, registry: data };
  } catch (err) {
    db.prepare(
      "UPDATE anchors SET status = 'failed' WHERE batch_id = ?"
    ).run(batchId);
    return { status: "failed", batch_id: batchId, error: err.message };
  }
}
