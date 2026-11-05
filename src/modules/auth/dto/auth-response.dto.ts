import { CodeSentDto } from '../../email-verification/dto';
import { UserResponseDto } from '../../users/dto';

export class KdfParamsResponseDto {
  salt: string;
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export class PreloginResponseDto {
  kdf: KdfParamsResponseDto;
}

export class TokenPairDto {
  tokenType: 'Bearer';
  accessToken: string;
  /** Segundos de vida del access token. */
  expiresIn: number;
  refreshToken: string;
}

export class AccountKeysDto {
  kdf: KdfParamsResponseDto;
  pvk: { ciphertext: string; nonce: string };
  keyVersion: number;
}

export class AuthResponseDto {
  requiresEmailVerification: false;
  requires2FA: false;
  tokens: TokenPairDto;
  user: UserResponseDto;
  keys: AccountKeysDto;
}

export class TwoFactorChallengeDto {
  requiresEmailVerification: false;
  requires2FA: true;
  /** Token de 5 minutos que solo sirve para completar la verificación TOTP. */
  challengeToken: string;
}

/**
 * Registro, o login con correo sin verificar: no hay sesión todavía. El cliente
 * pide el código al usuario y llama a /auth/email/verify/confirm.
 */
export class EmailVerificationRequiredDto {
  requiresEmailVerification: true;
  requires2FA: false;
  /** Token de 30 min que solo sirve para confirmar o reenviar el código. */
  challengeToken: string;
  verification: CodeSentDto;
}
