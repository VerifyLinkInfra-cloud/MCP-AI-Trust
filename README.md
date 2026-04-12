# VLI AI Trust Protocol

**Cryptographic accountability for AI decisions.**

Every AI action — every data access, every recommendation, every decision — sealed with Ed25519 signatures, SHA-256 hashing, and Merkle-anchored proof chains. Tamper-evident. Independently verifiable. Works across any system, any industry.

## What It Does

When an AI makes a decision, this MCP server creates a **cryptographic proof chain** that proves:

- **What** the AI decided
- **What data** it accessed
- **When** it happened
- **That nothing was altered** after the fact

Every event is signed with Ed25519, hash-linked to the previous event, and optionally anchored to a public transparency registry.

## Install

```bash
# Clone and install
git clone https://github.com/VerifyLinkInfra-cloud/mcp-ai-trust.git
cd mcp-ai-trust
npm install
```

### Claude Code

Add to your Claude Code MCP settings (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "ai-trust": {
      "command": "node",
      "args": ["/path/to/mcp-ai-trust/src/server.js"]
    }
  }
}
```

### Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `VLI_REGISTRY_URL` | `https://verifylinkinfra.com/registry-api` | VLI transparency registry for Merkle anchoring |
| `VLI_AGENT_ID` | `claude-code` | Identifier for this AI agent |
| `VLI_AGENT_NAME` | `Claude Code AI` | Human-readable agent name |
| `VLI_TRUST_DATA_DIR` | `./data` | Directory for the SQLite proof store |

## Tools

### `ai_begin_session`

Start a sealed AI session. Declares intent and purpose.

```
Input:  { purpose: "Review patient intake forms", model: "claude-opus-4-6" }
Output: { session_id: "ses-abc123", seal: { event_id, chain_hash, signature } }
```

### `ai_seal_decision`

Seal an AI decision with cryptographic proof.

```
Input:  { session_id, decision: "Recommend Treatment A", inputs: ["lab results", "history"],
          reasoning: "Patient shows indicators for...", confidence: 0.92, category: "clinical" }
Output: { event_id, proof: { payload_hash, chain_hash, seq, signature } }
```

### `ai_seal_access`

Record that the AI accessed sensitive data. Critical for HIPAA, SOX, GDPR.

```
Input:  { session_id, resource_type: "phi", resource_name: "Patient Record #1234",
          access_type: "read", justification: "Required for treatment recommendation" }
Output: { event_id, proof: { payload_hash, chain_hash, seq } }
```

### `ai_checkpoint`

Mid-workflow checkpoint for long-running tasks.

```
Input:  { session_id, label: "analysis_complete", notes: "Reviewed 47 records" }
Output: { event_id, label, seq, chain_hash }
```

### `ai_end_session`

Close the session, create a Merkle batch, and optionally anchor to the VLI registry.

```
Input:  { session_id, outcome: "Treatment plan generated", anchor: true }
Output: { events_sealed: 8, chain_integrity: "VALID", merkle_root: "a1b2c3...",
          anchor: { status: "anchored", registry: {...} }, public_key: "302a..." }
```

### `ai_verify`

Verify any sealed event or an entire session's proof chain.

```
Input:  { event_id: "ait-abc123" }
Output: { valid: true, payload_valid: true, signature_valid: true, payload: {...} }

Input:  { session_id: "ses-abc123" }
Output: { chain_valid: true, events_checked: 8, errors: [], events: [...] }
```

## How the Proof Chain Works

```
Event 0 (session start)
  payload_hash = SHA-256(canonical(payload))
  chain_hash   = SHA-256("genesis:session_id" + ":" + payload_hash)
  signature    = Ed25519.sign(chain_hash, private_key)

Event 1 (data access)
  payload_hash = SHA-256(canonical(payload))
  chain_hash   = SHA-256(event_0.chain_hash + ":" + payload_hash)
  signature    = Ed25519.sign(chain_hash, private_key)

Event 2 (decision)
  payload_hash = SHA-256(canonical(payload))
  chain_hash   = SHA-256(event_1.chain_hash + ":" + payload_hash)
  signature    = Ed25519.sign(chain_hash, private_key)

  ... and so on. Each event links to the previous.
  Tampering with ANY event breaks the chain.
```

### Merkle Anchoring

When a session ends, all events are batched into a Merkle tree. The root hash is submitted to the VLI transparency registry — a public, append-only log that proves the batch existed at a specific point in time.

## Industry Applications

| Industry | AI Action | What Gets Sealed |
|----------|-----------|-----------------|
| Healthcare | AI recommends treatment | Inputs, recommendation, reasoning, confidence |
| Finance | AI approves/denies loan | Application data accessed, decision factors, outcome |
| Legal | AI reviews contract | Clauses analyzed, risks flagged, recommendations |
| Defense | AI processes intelligence | Data accessed, analysis, conclusions |
| Manufacturing | AI controls production | Sensor inputs, decisions, quality parameters |

## Protocol Spec

- **Signing**: Ed25519 (RFC 8032)
- **Hashing**: SHA-256
- **Canonicalization**: Deterministic JSON (sorted keys, RFC 8785-like)
- **Chain Linking**: Each event's chain_hash = SHA-256(prev_chain_hash + ":" + payload_hash)
- **Batching**: Binary Merkle tree of chain_hashes
- **Anchoring**: Merkle root submitted to VLI transparency registry
- **Storage**: Local SQLite (portable, zero-config)
- **Transport**: MCP (Model Context Protocol) over stdio

## License

Apache 2.0

## Built by

[VerifyLink Infrastructure](https://verifylinkinfra.com) — Protocol-first trust infrastructure.
