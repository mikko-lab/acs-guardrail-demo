# ACS Guardrail Demo - Phase 1

**This project demonstrates selected ACS v0.1.0 control patterns. It does not claim ACS-Core conformance.**

This is a standalone, public demo of a deterministic Agent Control Standard (ACS) control flow. It proves how an external, deterministic guardian policy can mediate AI agent tool calls before they execute, recording an audit trail and securely gating side-effects behind explicit human approval.

## Non-Goals & Limitations

This first slice intentionally **DOES NOT** implement:
- Full ACS hook taxonomy
- Handshake
- HMAC envelope signatures
- Replay protection
- `modify` or `defer` decisions
- SessionContext
- Wrapped MCP
- ACS-Trace, ACS-Inspect / AgBOM, ACS-Provenance, ACS-Crypto, ACS-Audit

See the detailed crosswalk analysis in [docs/acs-crosswalk.md](./docs/acs-crosswalk.md).

## Purpose

To demonstrate a zero-dependency, local execution gate that honors a deterministic Guardian decision without relying on LLM self-correction or probabilistic prompts. 

## Architecture

```text
Agent requests tool call
        ↓
Guardian evaluates deterministic policy
        ↓
ALLOW / DENY / ASK
        ↓
Execution gate honors decision
        ↓
Tool executes or does not execute
        ↓
Result + minimal audit evidence
```

## Demo Policies

1. **`read_record`** 
   - Read-only action. Guardian decides `ALLOW`. Executes exactly once.
2. **`update_record`**
   - Side-effect action. Guardian decides `ASK`. Requires explicit human approval bound to the exact `request_id` before execution.
3. **Unknown Tools**
   - Fallback. Guardian decides `DENY`. Never executes.

## Human Approval (`ASK` decision

> **ACS field naming note:** The ACS v0.1.0 response envelope (response-envelope.json) names the verdict field **`decision`**, not `disposition`. The vocabulary values are `allow`, `deny`, `ask`, `modify`, and `defer`. This demo uses the correct ACS field name throughout.

Approval cannot be manufactured by the Guardian or the AI agent. The execution gate explicitly requires `supplyApproval(request_id)` from an external, trusted human interaction layer. Approval for Request A never authorizes Request B.

## Security Properties Demonstrated

- Deterministic policy enforcement isolated from the LLM prompt.
- Explicit blocking of unknown actions.
- Requirement for externally-supplied human approval on sensitive actions.
- Audit trailing of all lifecycle events (request, decision, execution, block).

## Usage

### Run Tests
```bash
npm install
npx jest
```

### Run Demo
```bash
npx ts-node src/demo.ts
```
