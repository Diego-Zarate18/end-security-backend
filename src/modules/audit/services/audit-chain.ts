import { createHmac } from 'crypto';
import { AUDIT_HASH_VERSION } from '../audit.constants';

export interface AuditChainEntry {
  id: bigint;
  prevHash: Uint8Array | null;
  userId: string;
  eventType: string;
  outcome: string;
  occurredAt: Date;
  metadata: unknown;
}

/** JSON con claves ordenadas recursivamente: misma entrada, mismos bytes. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value !== null && typeof value === 'object' && !(value instanceof Date)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

/**
 * HMAC-SHA256 de una entrada encadenada con la anterior del mismo usuario.
 *
 * Es HMAC y no un hash simple: quien solo tenga acceso a la base de datos no
 * puede recalcular la cadena después de alterar filas.
 *
 * `session_id` no entra al cálculo porque la FK es ON DELETE SET NULL: limpiar
 * sesiones viejas no debe romper la cadena. La IP y el User-Agent viven en
 * `audit_log_pii` por la misma razón (se pueden borrar por retención).
 */
export function computeAuditHash(
  key: Buffer,
  entry: AuditChainEntry,
): Uint8Array<ArrayBuffer> {
  const payload = canonicalJson({
    v: AUDIT_HASH_VERSION,
    id: entry.id.toString(),
    prev: entry.prevHash ? Buffer.from(entry.prevHash).toString('hex') : null,
    user: entry.userId,
    event: entry.eventType,
    outcome: entry.outcome,
    at: entry.occurredAt.toISOString(),
    metadata: entry.metadata ?? {},
  });
  const digest = createHmac('sha256', key).update(payload).digest();
  const out = new Uint8Array(digest.length);
  out.set(digest);
  return out;
}
