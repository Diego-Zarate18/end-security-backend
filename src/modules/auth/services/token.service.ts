import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { parseDurationMs } from '../../../common/utils';
import {
  EMAIL_CHALLENGE_TTL_SECONDS,
  TokenType,
  TWO_FACTOR_CHALLENGE_TTL_SECONDS,
} from '../auth.constants';

export interface ChallengeClaims {
  userId: string;
  deviceName: string;
}

const REFRESH_TOKEN_PATTERN = /^([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/;

/**
 * Emisión de JWT y manejo criptográfico de refresh tokens.
 * Los refresh tokens son opacos (`<sessionId>.<32 bytes base64url>`) y en BD
 * solo se guarda su HMAC-SHA256 con un pepper del servidor.
 */
@Injectable()
export class TokenService {
  private readonly pepper: Buffer;
  readonly accessTtlSeconds: number;
  readonly refreshTtlMs: number;

  constructor(
    private readonly jwtService: JwtService,
    configService: ConfigService,
  ) {
    this.pepper = Buffer.from(
      configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      'utf8',
    );
    this.accessTtlSeconds = Math.floor(
      parseDurationMs(configService.get<string>('JWT_EXPIRES_IN') ?? '15m') /
        1000,
    );
    this.refreshTtlMs = parseDurationMs(
      configService.get<string>('JWT_REFRESH_EXPIRES_IN') ?? '7d',
    );
  }

  signAccessToken(userId: string, sessionId: string): string {
    return this.jwtService.sign(
      { sub: userId, sid: sessionId, typ: TokenType.Access },
      { expiresIn: this.accessTtlSeconds },
    );
  }

  signTwoFactorChallenge(userId: string, deviceName: string): string {
    return this.jwtService.sign(
      { sub: userId, typ: TokenType.TwoFactorPending, dn: deviceName },
      { expiresIn: TWO_FACTOR_CHALLENGE_TTL_SECONDS },
    );
  }

  signEmailVerificationChallenge(userId: string, deviceName: string): string {
    return this.jwtService.sign(
      { sub: userId, typ: TokenType.EmailVerificationPending, dn: deviceName },
      { expiresIn: EMAIL_CHALLENGE_TTL_SECONDS },
    );
  }

  /**
   * Valida un token de desafío (correo pendiente o 2FA) del tipo esperado.
   * Un access token o un desafío de otro tipo se rechazan.
   */
  verifyChallenge(token: string, expected: TokenType): ChallengeClaims {
    try {
      const payload = this.jwtService.verify<{
        sub?: string;
        typ?: string;
        dn?: string;
      }>(token);
      if (payload.typ === expected && payload.sub && payload.dn) {
        return { userId: payload.sub, deviceName: payload.dn };
      }
    } catch {
      // firma inválida o vencido: mismo mensaje
    }
    throw new UnauthorizedException(
      'El desafío no es válido o ya venció. Inicia sesión de nuevo.',
    );
  }

  generateRefreshSecret(): string {
    return randomBytes(32).toString('base64url');
  }

  buildRefreshToken(sessionId: string, secret: string): string {
    return `${sessionId}.${secret}`;
  }

  parseRefreshToken(
    token: string,
  ): { sessionId: string; secret: string } | null {
    const match = REFRESH_TOKEN_PATTERN.exec(token);
    return match ? { sessionId: match[1], secret: match[2] } : null;
  }

  hashRefreshSecret(secret: string): Uint8Array<ArrayBuffer> {
    return this.hmac(`refresh:${secret}`);
  }

  /** Salt determinista para correos inexistentes en /auth/prelogin. */
  fakeKdfSalt(email: string): Uint8Array<ArrayBuffer> {
    return this.hmac(`prelogin-salt:${email}`).slice(0, 16);
  }

  safeEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && timingSafeEqual(a, b);
  }

  private hmac(input: string): Uint8Array<ArrayBuffer> {
    const digest = createHmac('sha256', this.pepper).update(input).digest();
    const out = new Uint8Array(digest.length);
    out.set(digest);
    return out;
  }
}
