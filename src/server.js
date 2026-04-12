#!/usr/bin/env node

/**
 * VLI AI Trust Protocol — MCP Server
 *
 * Cryptographic accountability for AI decisions.
 * Every AI action sealed with Ed25519 + SHA-256 + chain linking.
 *
 * Tools:
 *   ai_begin_session  — Declare AI intent, start a sealed session
 *   ai_seal_decision  — Seal an AI decision (inputs + outputs + reasoning)
 *   ai_seal_access    — Record AI data access (PHI, PII, financials, etc.)
 *   ai_checkpoint     — Mid-workflow checkpoint seal
 *   ai_end_session    — Close session, create Merkle anchor batch
 *   ai_verify         — Verify any sealed event or full session chain
 *
 * Install in Claude Code:
 *   Add to settings.json mcpServers:
 *   "ai-trust": { "command": "node", "args": ["/path/to/mcp-ai-trust/src/server.js"] }
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { getDb, getKeys } from "./lib/store.js";
import { sealEvent, verifyChain, verifyEvent, createAnchorBatch, submitAnchor } from "./lib/proof-chain.js";
import { randomId, sha256 } from "./lib/crypto.js";

// ═══════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════

const REGISTRY_URL = process.env.VLI_REGISTRY_URL || "https://verifylinkinfra.com/registry-api";
const ART_API = process.env.VLI_ART_API || "https://vliworkspaces.com/api";
const ART_TOKEN = process.env.VLI_ART_TOKEN || process.env.VLI_AUTH_TOKEN || "";
const ART_ORG_ID = process.env.VLI_ORG_ID || "";
const AGENT_ID = process.env.VLI_AGENT_ID || "claude-code";
const AGENT_NAME = process.env.VLI_AGENT_NAME || "Claude Code AI";
const AGENT_MODEL = process.env.VLI_AGENT_MODEL || "claude-opus-4-6";
const AGENT_VENDOR = process.env.VLI_AGENT_VENDOR || "Anthropic";

// Initialize DB on startup
getDb();

// ═══════════════════════════════════════════════════════════════
// ART Integration — Agent Registry & Trust
// ═══════════════════════════════════════════════════════════════

let _artAgent = null; // cached ART registration

async function artFetch(path, opts = {}) {
  if (!ART_API || !ART_TOKEN) return null;
  try {
    const res = await fetch(`${ART_API}${path}`, {
      ...opts,
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${ART_TOKEN}`,
        "X-Org-Id": ART_ORG_ID,
        ...opts.headers,
      },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

/**
 * Look up or auto-register this AI agent in the ART registry.
 * Returns { system_id, art_id, status, data_access } or null.
 */
async function resolveArtAgent() {
  if (_artAgent) return _artAgent;
  if (!ART_API || !ART_TOKEN || !ART_ORG_ID) return null;

  // Try to find existing registration by name
  const list = await artFetch(`/orgs/${ART_ORG_ID}/ai-systems`);
  if (list?.systems) {
    const existing = list.systems.find(s => s.name === AGENT_NAME || s.name === AGENT_ID);
    if (existing) {
      _artAgent = existing;
      console.error(`[ai-trust] ART agent found: ${existing.art_id} (${existing.name})`);
      return _artAgent;
    }
  }

  // Auto-register
  const reg = await artFetch(`/orgs/${ART_ORG_ID}/ai-systems`, {
    method: "POST",
    body: JSON.stringify({
      name: AGENT_NAME,
      vendor: AGENT_VENDOR,
      model_version: AGENT_MODEL,
      purpose: "AI assistant with sealed decision accountability via VLI AI Trust Protocol",
      risk_tier: "medium",
      data_access: ["read-only (project files, documentation)", "analysis (code review, compliance checks)"],
      phi_access: false,
    }),
  });

  if (reg?.art_id) {
    console.error(`[ai-trust] ART agent registered: ${reg.art_id}`);
    // Fetch full record
    const full = await artFetch(`/orgs/${ART_ORG_ID}/ai-systems/${reg.system_id}`);
    _artAgent = full?.system || { system_id: reg.system_id, art_id: reg.art_id, name: AGENT_NAME };
    return _artAgent;
  }

  return null;
}

/**
 * Record a sealed AI event as an ART output for provenance tracking.
 */
async function recordArtOutput(systemId, eventType, sealResult, extraData = {}) {
  if (!systemId || !ART_API || !ART_TOKEN) return;
  await artFetch(`/orgs/${ART_ORG_ID}/ai-systems/${systemId}/outputs`, {
    method: "POST",
    body: JSON.stringify({
      output_type: eventType,
      output_data: { ...extraData, seal_event_id: sealResult.event_id, chain_hash: sealResult.chain_hash },
      input_data: extraData.inputs || null,
    }),
  });
}

// ═══════════════════════════════════════════════════════════════
// MCP Server
// ═══════════════════════════════════════════════════════════════

const server = new McpServer({
  name: "vli-ai-trust",
  version: "0.1.0",
});

function fmt(data) {
  return typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

// ───────────────────────────────────────────────────────────────
// Tool 1: ai_begin_session
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_begin_session",
  "Start a sealed AI session. Declares what the AI intends to do, what model is running, and the purpose. Returns a session_id that must be passed to all subsequent seal calls.",
  {
    purpose: z.string().describe("What this AI session is for (e.g. 'Review patient intake forms', 'Analyze loan application')"),
    model: z.string().optional().describe("AI model identifier (e.g. 'claude-opus-4-6', 'gpt-4')"),
    context: z.record(z.any()).optional().describe("Additional context — org, user, environment"),
  },
  async ({ purpose, model, context }) => {
    const db = getDb();
    const sessionId = randomId("ses");
    const now = new Date().toISOString();

    // Resolve ART agent registration
    const artAgent = await resolveArtAgent();

    db.prepare(`
      INSERT INTO sessions (session_id, agent_id, agent_name, purpose, model, started_at, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(sessionId, AGENT_ID, AGENT_NAME, purpose, model || AGENT_MODEL, now,
      JSON.stringify({ ...context, art_id: artAgent?.art_id || null, art_system_id: artAgent?.system_id || null }));

    // Seal the session start
    const seal = sealEvent(sessionId, "ai.session_started", {
      event: "ai.session_started",
      session_id: sessionId,
      agent_id: AGENT_ID,
      agent_name: AGENT_NAME,
      art_id: artAgent?.art_id || null,
      purpose,
      model: model || AGENT_MODEL,
      started_at: now,
    });

    // Record in ART
    if (artAgent) {
      recordArtOutput(artAgent.system_id, "session_started", seal, { purpose });
    }

    return {
      content: [{
        type: "text",
        text: fmt({
          status: "session_started",
          session_id: sessionId,
          agent: AGENT_NAME,
          purpose,
          art: artAgent ? { art_id: artAgent.art_id, status: artAgent.status, registered: true } : { registered: false, reason: "No ART API configured or auth token missing" },
          seal: {
            event_id: seal.event_id,
            chain_hash: seal.chain_hash,
            signature: seal.signature.substring(0, 32) + "...",
          },
          instructions: "Pass this session_id to ai_seal_decision, ai_seal_access, ai_checkpoint, and ai_end_session.",
        }),
      }],
    };
  }
);

// ───────────────────────────────────────────────────────────────
// Tool 2: ai_seal_decision
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_seal_decision",
  "Seal an AI decision with cryptographic proof. Records what inputs the AI considered, what decision it made, and its reasoning. The decision becomes tamper-evident and independently verifiable.",
  {
    session_id: z.string().describe("Session ID from ai_begin_session"),
    decision: z.string().describe("The decision or recommendation the AI made"),
    inputs: z.array(z.string()).optional().describe("What data/inputs the AI considered"),
    reasoning: z.string().optional().describe("Why the AI made this decision"),
    confidence: z.number().optional().describe("Confidence score 0-1"),
    category: z.string().optional().describe("Decision category (e.g. 'clinical', 'financial', 'legal', 'operational')"),
    metadata: z.record(z.any()).optional().describe("Additional structured data"),
  },
  async ({ session_id, decision, inputs, reasoning, confidence, category, metadata }) => {
    const seal = sealEvent(session_id, "ai.decision", {
      event: "ai.decision",
      session_id,
      decision,
      inputs: inputs || [],
      reasoning: reasoning || null,
      confidence: confidence || null,
      category: category || "general",
      ...(metadata || {}),
      sealed_at: new Date().toISOString(),
    });

    // Record in ART as sealed output
    const artAgent = await resolveArtAgent();
    if (artAgent) {
      recordArtOutput(artAgent.system_id, "ai.decision", seal, { decision, category, confidence, inputs });
    }

    return {
      content: [{
        type: "text",
        text: fmt({
          status: "decision_sealed",
          art_tracked: !!artAgent,
          event_id: seal.event_id,
          decision: decision.substring(0, 100) + (decision.length > 100 ? "..." : ""),
          proof: {
            payload_hash: seal.payload_hash,
            chain_hash: seal.chain_hash,
            seq: seal.seq,
            signature: seal.signature.substring(0, 32) + "...",
          },
          tamper_evident: true,
          independently_verifiable: true,
        }),
      }],
    };
  }
);

// ───────────────────────────────────────────────────────────────
// Tool 3: ai_seal_access
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_seal_access",
  "Record that the AI accessed sensitive data. Creates a sealed audit record of what data was accessed, what type (PHI, PII, financial, classified), and why. Critical for HIPAA, SOX, GDPR compliance.",
  {
    session_id: z.string().describe("Session ID from ai_begin_session"),
    resource_type: z.string().describe("Type of data accessed (e.g. 'phi', 'pii', 'financial', 'classified', 'medical_record', 'contract')"),
    resource_id: z.string().optional().describe("Identifier of the specific resource"),
    resource_name: z.string().optional().describe("Human-readable name"),
    access_type: z.string().optional().describe("How it was accessed: 'read', 'write', 'analyze', 'summarize', 'classify'"),
    justification: z.string().optional().describe("Why the AI needed this data"),
    data_hash: z.string().optional().describe("SHA-256 hash of the data accessed (for proving what was seen without revealing content)"),
  },
  async ({ session_id, resource_type, resource_id, resource_name, access_type, justification, data_hash }) => {
    const seal = sealEvent(session_id, "ai.data_access", {
      event: "ai.data_access",
      session_id,
      resource_type,
      resource_id: resource_id || null,
      resource_name: resource_name || null,
      access_type: access_type || "read",
      justification: justification || null,
      data_hash: data_hash || null,
      accessed_at: new Date().toISOString(),
    });

    // Record in ART
    const artAgent = await resolveArtAgent();
    if (artAgent) {
      recordArtOutput(artAgent.system_id, "ai.data_access", seal, { resource_type, resource_name, access_type });
    }

    return {
      content: [{
        type: "text",
        text: fmt({
          status: "access_sealed",
          art_tracked: !!artAgent,
          event_id: seal.event_id,
          resource_type,
          resource_name: resource_name || resource_id || "—",
          access_type: access_type || "read",
          proof: {
            payload_hash: seal.payload_hash,
            chain_hash: seal.chain_hash,
            seq: seal.seq,
          },
        }),
      }],
    };
  }
);

// ───────────────────────────────────────────────────────────────
// Tool 4: ai_checkpoint
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_checkpoint",
  "Create a mid-workflow checkpoint seal. Use during long-running AI tasks to periodically seal progress. Records current state, partial results, and any intermediate decisions.",
  {
    session_id: z.string().describe("Session ID from ai_begin_session"),
    label: z.string().describe("Checkpoint label (e.g. 'analysis_complete', 'data_collected', 'review_phase_2')"),
    state: z.record(z.any()).optional().describe("Current state/progress data"),
    notes: z.string().optional().describe("Human-readable progress notes"),
  },
  async ({ session_id, label, state, notes }) => {
    const seal = sealEvent(session_id, "ai.checkpoint", {
      event: "ai.checkpoint",
      session_id,
      label,
      state: state || {},
      notes: notes || null,
      checkpoint_at: new Date().toISOString(),
    });

    return {
      content: [{
        type: "text",
        text: fmt({
          status: "checkpoint_sealed",
          event_id: seal.event_id,
          label,
          seq: seal.seq,
          chain_hash: seal.chain_hash,
        }),
      }],
    };
  }
);

// ───────────────────────────────────────────────────────────────
// Tool 5: ai_end_session
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_end_session",
  "End a sealed AI session. Seals the final event, creates a Merkle batch of all session events, and optionally anchors to the VLI transparency registry. Returns the complete session proof summary.",
  {
    session_id: z.string().describe("Session ID to close"),
    outcome: z.string().optional().describe("Session outcome summary"),
    anchor: z.boolean().optional().describe("Whether to anchor the batch to VLI registry (default: true if configured)"),
  },
  async ({ session_id, outcome, anchor }) => {
    const db = getDb();
    const session = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(session_id);
    if (!session) {
      return { content: [{ type: "text", text: fmt({ error: "Session not found: " + session_id }) }] };
    }

    // Seal the end event
    const seal = sealEvent(session_id, "ai.session_ended", {
      event: "ai.session_ended",
      session_id,
      outcome: outcome || null,
      event_count: session.event_count + 1,
      ended_at: new Date().toISOString(),
    });

    // Close the session
    db.prepare(
      "UPDATE sessions SET status = 'completed', ended_at = ? WHERE session_id = ?"
    ).run(new Date().toISOString(), session_id);

    // Create Merkle anchor batch
    const batch = createAnchorBatch();

    // Optionally anchor to VLI registry
    let anchorResult = null;
    if ((anchor !== false) && batch && REGISTRY_URL) {
      try {
        anchorResult = await submitAnchor(batch.batch_id, REGISTRY_URL);
      } catch (e) {
        anchorResult = { status: "skipped", reason: e.message };
      }
    }

    // Verify the chain
    const verification = verifyChain(session_id);

    return {
      content: [{
        type: "text",
        text: fmt({
          status: "session_completed",
          session_id,
          purpose: session.purpose,
          events_sealed: session.event_count + 1,
          duration_ms: new Date() - new Date(session.started_at),
          chain_integrity: verification.valid ? "VALID" : "BROKEN",
          final_chain_hash: seal.chain_hash,
          batch: batch ? {
            batch_id: batch.batch_id,
            event_count: batch.event_count,
            merkle_root: batch.merkle_root,
          } : null,
          anchor: anchorResult,
          public_key: getKeys().publicKey,
          verifiable: "Any third party can independently verify this session's proof chain using the public key and event hashes.",
        }),
      }],
    };
  }
);

// ───────────────────────────────────────────────────────────────
// Tool 6: ai_verify
// ───────────────────────────────────────────────────────────────
server.tool(
  "ai_verify",
  "Verify a sealed AI event or an entire session's proof chain. Checks payload hashes, chain links, and Ed25519 signatures. Proves nothing was tampered with.",
  {
    event_id: z.string().optional().describe("Verify a specific sealed event by ID"),
    session_id: z.string().optional().describe("Verify an entire session's chain integrity"),
  },
  async ({ event_id, session_id }) => {
    if (event_id) {
      const result = verifyEvent(event_id);
      return { content: [{ type: "text", text: fmt(result) }] };
    }

    if (session_id) {
      const db = getDb();
      const session = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(session_id);
      const chain = verifyChain(session_id);
      const events = db.prepare(
        "SELECT event_id, event_type, seq, payload_hash, chain_hash, created_at FROM events WHERE session_id = ? ORDER BY seq ASC"
      ).all(session_id);

      return {
        content: [{
          type: "text",
          text: fmt({
            session_id,
            purpose: session?.purpose,
            status: session?.status,
            chain_valid: chain.valid,
            events_checked: chain.events_checked,
            errors: chain.errors,
            public_key: chain.public_key,
            events: events.map(e => ({
              seq: e.seq,
              type: e.event_type,
              hash: e.payload_hash.substring(0, 16) + "...",
              chain: e.chain_hash.substring(0, 16) + "...",
              time: e.created_at,
            })),
          }),
        }],
      };
    }

    return { content: [{ type: "text", text: "Provide either event_id or session_id to verify." }] };
  }
);

// ═══════════════════════════════════════════════════════════════
// Start Server
// ═══════════════════════════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[ai-trust] VLI AI Trust Protocol server running");
  console.error("[ai-trust] Public key: " + getKeys().publicKey.substring(0, 24) + "...");
}

main().catch((err) => {
  console.error("[ai-trust] Fatal:", err);
  process.exit(1);
});
