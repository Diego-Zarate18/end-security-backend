/**
 * TOTP_ENCRYPTION_KEYS="1:<base64 de 32 bytes>,2:<base64 de 32 bytes>"
 * La de id más alto cifra los secretos nuevos; las demás solo descifran.
 */
export function parseTotpKeys(raw: string): {
  keys: Map<number, Buffer>;
  currentKeyId: number;
} {
  const keys = new Map<number, Buffer>();
  for (const entry of raw
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean)) {
    const match = /^(\d{1,4}):([A-Za-z0-9+/]+={0,2})$/.exec(entry);
    if (!match) {
      throw new Error('TOTP_ENCRYPTION_KEYS debe tener el formato id:base64.');
    }
    const id = Number(match[1]);
    const key = Buffer.from(match[2], 'base64');
    if (id < 1 || id > 32767 || key.length !== 32 || keys.has(id)) {
      throw new Error(
        'Cada clave de TOTP_ENCRYPTION_KEYS necesita un id único (1-32767) y 32 bytes.',
      );
    }
    keys.set(id, key);
  }
  if (keys.size === 0) {
    throw new Error('TOTP_ENCRYPTION_KEYS no tiene ninguna clave.');
  }
  return { keys, currentKeyId: Math.max(...keys.keys()) };
}
