import * as argon2 from 'argon2';
import { fromBase64 } from '../../common/utils';
import type { PrismaService } from '../../database/prisma.service';

const LOCK_MAX_FAILURES = 5;
const LOCK_WINDOW_MS = 15 * 60_000;

/**
 * Compara el auth key que envía el cliente (base64) con el hash Argon2id
 * guardado. Función pura: la usan el login y las reautenticaciones
 * (cambio de correo, 2FA, borrado de cuenta) sin depender de AuthModule.
 */
export function verifyAuthHash(
  storedHash: string,
  authHashBase64: string,
): Promise<boolean> {
  return argon2
    .verify(storedHash, Buffer.from(fromBase64(authHashBase64)))
    .catch(() => false);
}

/**
 * Límite por cuenta (BR-22): 5 contraseñas incorrectas en 15 minutos, sumando
 * login y reautenticaciones, bloquean la cuenta hasta que el más viejo salga
 * de la ventana. Se cuenta en audit_log, que ya registra cada fallo.
 */
export async function isAccountLocked(
  prisma: PrismaService,
  userId: string,
): Promise<boolean> {
  const failures = await prisma.audit_log.count({
    where: {
      user_id: userId,
      outcome: 'failure',
      metadata: { path: ['reason'], equals: 'invalid_credentials' },
      occurred_at: { gte: new Date(Date.now() - LOCK_WINDOW_MS) },
    },
  });
  return failures >= LOCK_MAX_FAILURES;
}
