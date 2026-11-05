import * as argon2 from 'argon2';

/** Tipos de JWT emitidos. El guard global solo acepta `access`. */
export enum TokenType {
  Access = 'access',
  TwoFactorPending = '2fa_pending',
  EmailVerificationPending = 'email_pending',
}

/**
 * Parámetros KDF por defecto que el cliente usa al registrarse. También se
 * devuelven en /auth/prelogin para correos inexistentes, de modo que la
 * respuesta no permita enumerar cuentas.
 */
export const DEFAULT_KDF_PARAMS = {
  memoryKib: 65536,
  iterations: 3,
  parallelism: 4,
} as const;

/** Argon2id del lado del servidor sobre el auth key que envía el cliente. */
export const SERVER_ARGON2_OPTIONS: argon2.HashOptions = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

export const TWO_FACTOR_CHALLENGE_TTL_SECONDS = 300;

/** Más largo que la vigencia del código (15 min) para permitir reenvíos. */
export const EMAIL_CHALLENGE_TTL_SECONDS = 1800;
