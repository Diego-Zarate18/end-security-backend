import * as argon2 from 'argon2';
import { fromBase64 } from '../../common/utils';

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
