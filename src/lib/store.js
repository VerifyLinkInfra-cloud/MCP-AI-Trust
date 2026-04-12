/**
 * VLI AI Trust Protocol — Local Proof Store
 *
 * SQLite-backed storage for sessions, sealed events, and proof chains.
 * Self-contained — works offline, anchors to VLI registry when configured.
 */
import Database from "better-sqlite3";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { existsSync, mkdirSync } from "fs";
import { generateKeypair } from "./crypto.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

let _db;
let _keys;

/**
 * Get or initialize the database.
 */
export function getDb() {
  if (_db) return _db;

  const dataDir = process.env.VLI_TRUST_DATA_DIR || join(__dirname, "..", "..", "data");
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });

  const dbPath = process.env.VLI_TRUST_DB_PATH || join(dataDir, "ai-trust.db");
  _db = new Database(dbPath);
  _db.pragma("journal_mode = WAL");
  _db.pragma("foreign_keys = ON");
  _db.exec(SCHEMA);

  // Ensure we have a keypair
  const existing = _db.prepare("SELECT * FROM config WHERE key = 'public_key'").get();
  if (!existing) {
    const keys = generateKeypair();
    _db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run("public_key", keys.publicKey);
    _db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run("private_key", keys.privateKey);
    _db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run("created_at", new Date().toISOString());
    console.error("[ai-trust] Generated new Ed25519 keypair");
  }

  return _db;
}

/**
 * Get the signing keypair.
 */
export function getKeys() {
  if (_keys) return _keys;
  const db = getDb();
  _keys = {
    publicKey: db.prepare("SELECT value FROM config WHERE key = 'public_key'").get().value,
    privateKey: db.prepare("SELECT value FROM config WHERE key = 'private_key'").get().value,
  };
  return _keys;
}

export function close() {
  if (_db) { _db.close(); _db = null; _keys = null; }
}

const SCHEMA = `
  -- Configuration (keypair, settings)
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  -- AI Sessions
  CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL,
    agent_name    TEXT,
    purpose       TEXT,
    model         TEXT,
    started_at    TEXT NOT NULL,
    ended_at      TEXT,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','abandoned')),
    event_count   INTEGER NOT NULL DEFAULT 0,
    anchor_batch  TEXT,
    metadata      TEXT DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

  -- Sealed Events (the core proof chain)
  CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id),
    event_type     TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    payload_json   TEXT NOT NULL,
    payload_hash   TEXT NOT NULL,
    prev_hash      TEXT,
    chain_hash     TEXT NOT NULL,
    signature      TEXT NOT NULL,
    created_at     TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
  CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

  -- Anchor Batches (Merkle roots submitted to registry)
  CREATE TABLE IF NOT EXISTS anchors (
    batch_id       TEXT PRIMARY KEY,
    event_count    INTEGER NOT NULL,
    merkle_root    TEXT NOT NULL,
    registry_ref   TEXT,
    status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','anchored','failed')),
    created_at     TEXT NOT NULL,
    anchored_at    TEXT
  );
`;
