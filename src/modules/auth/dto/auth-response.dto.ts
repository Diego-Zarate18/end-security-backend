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
  requires2FA: false;
  tokens: TokenPairDto;
  user: UserResponseDto;
  keys: AccountKeysDto;
}

export class TwoFactorChallengeDto {
  requires2FA: true;
  /** Token de 5 minutos que solo sirve para completar la verificación TOTP. */
  challengeToken: string;
}
