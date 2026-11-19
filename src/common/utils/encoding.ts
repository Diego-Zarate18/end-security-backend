/**
 * Utilidades de codificación para el transporte de material criptográfico.
 * La API expone BYTEA como base64 y BIGINT como number (seguro hasta 2^53 - 1).
 */
export function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const buffer = Buffer.from(value, 'base64');
  const out = new Uint8Array(buffer.length);
  out.set(buffer);
  return out;
}

export function bigintToNumber(value: bigint): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < 0n) {
    throw new RangeError('Valor BIGINT fuera del rango seguro de la API.');
  }
  return Number(value);
}

const DURATION_UNITS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** Convierte duraciones tipo "15m", "7d" o "3600" (segundos) a milisegundos. */
export function parseDurationMs(value: string): number {
  const match = /^(\d+)\s*(ms|s|m|h|d)?$/.exec(value.trim());
  if (!match) {
    throw new Error(`Duración inválida: "${value}"`);
  }
  return Number(match[1]) * DURATION_UNITS[match[2] ?? 's'];
}
