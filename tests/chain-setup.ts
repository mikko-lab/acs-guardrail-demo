/**
 * Test setup for ancestor chains (package 1b). The harness acts as the trusted issuer: it signs every chain member
 * with the issuer key of tests/tenant-setup.ts, links each child to its parent by capability_id and content
 * fingerprint, and its capability provider returns the leaf with its complete ancestor chain.
 *
 * Member times are nested so that a valid chain always passes attenuation: the member at position i (0 = leaf) is
 * issued at now - 1000 - 1000*i and expires at now + 300000 + 1000*i. The clock is never advanced (see
 * tests/tenant-setup.ts).
 */
import crypto from "crypto";
import { canonicalize } from "json-canonicalize";
import { capabilityFingerprint, CapabilityParentRef } from "../src/capability-grant";
import type { CapabilityLookupContext } from "../src/guarded-executor";
import { fresh } from "./evals/eval-setup";
import { sessionUuid, TenancyCtx } from "./tenant-setup";

export interface MemberSpec {
  id: string;
  tenant?: string;
  /** Runtime session the member names; the leaf defaults to the request session, ancestors to their own session. */
  session?: string;
  tools?: string[];
  /** Offsets from now in ms; default from the member's position (see above). */
  issued?: number;
  expires?: number;
  /** Replaces the computed parent reference (null: no parent reference). */
  parent?: CapabilityParentRef | null;
  /** Signs the member with a key the verifier does not trust. */
  untrusted?: boolean;
}

export type Grant = Record<string, unknown>;
export interface ChainEnvelope { kind: "capability_chain"; leaf: Grant; ancestors: Grant[] }

const untrustedKey = crypto.generateKeyPairSync("ed25519").privateKey;

/** Signs one member body with the trusted issuer key (or an untrusted one). */
export function signMember(ctx: TenancyCtx, body: Grant, untrusted = false): Grant {
  if (!untrusted) return ctx.provider.sign(body);
  const value = crypto.sign(null, Buffer.from(canonicalize(body)), untrustedKey).toString("base64");
  return { ...body, signature: { algorithm: "Ed25519", key_id: "cap-key-1", value } };
}

export const parentRef = (parent: Grant): CapabilityParentRef =>
  ({ capability_id: parent.capability_id as string, fingerprint: capabilityFingerprint(parent) });

/** One signed member at chain position `position`, optionally linked to `parent`. */
export function member(ctx: TenancyCtx, spec: MemberSpec, position: number, leafSession: string, parent?: Grant): Grant {
  const now = ctx.clock.nowMs();
  const ref = spec.parent === null ? undefined : spec.parent ?? (parent ? parentRef(parent) : undefined);
  return signMember(ctx, {
    version: 2,
    capability_id: spec.id,
    agent_id: "agent-test",
    session_id: spec.session !== undefined ? sessionUuid(spec.session) : position === 0 ? leafSession : sessionUuid(`anc-${spec.id}`),
    tenant_id: spec.tenant ?? "t1",
    ...(ref ? { parent: ref } : {}),
    allowed_tools: spec.tools ?? ["read_record", "update_record"],
    issued_at: fresh(now, spec.issued ?? -1000 - 1000 * position),
    expires_at: fresh(now, spec.expires ?? 300000 + 1000 * position),
  }, spec.untrusted);
}

/**
 * Builds a chain from specs ordered leaf first, root last; each member links to the next. `leafSession` is the
 * request's session (a name passed to sessionUuid).
 */
export function chain(ctx: TenancyCtx, leafSession: string, specs: MemberSpec[]): ChainEnvelope {
  const members: Grant[] = new Array(specs.length);
  for (let i = specs.length - 1; i >= 0; i--) members[i] = member(ctx, specs[i], i, sessionUuid(leafSession), members[i + 1]);
  return { kind: "capability_chain", leaf: members[0], ancestors: members.slice(1) };
}

/** Makes the provider answer every lookup of a session with the given envelope (by session name). */
export function serveChains(ctx: TenancyCtx, bySession: Record<string, ChainEnvelope | Grant>): void {
  const table = new Map(Object.entries(bySession).map(([name, answer]) => [sessionUuid(name), answer]));
  ctx.provider.answerFor = (context: CapabilityLookupContext) => table.get(context.session_id);
}

/** Replaces the answer for one session (by name) in the table set up by serveChains. */
export function serveChain(ctx: TenancyCtx, session: string, answer: ChainEnvelope | Grant): void {
  const previous = ctx.provider.answerFor;
  const id = sessionUuid(session);
  ctx.provider.answerFor = (context: CapabilityLookupContext) => (context.session_id === id ? answer : previous?.(context));
}
