import { Injectable, UnauthorizedException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { randomUUID } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { TokenPairDto } from '../dto';
import { TokenService } from './token.service';

export type SessionRevokeReason =
  | 'logout'
  | 'refresh_token_reuse'
  | 'revoked_by_user'
  | 'password_change'
  | 'email_change'
  | 'account_deleted';

export interface CreatedSession {
  sessionId: string;
  tokens: TokenPairDto;
}

const invalidRefresh = () =>
  new UnauthorizedException('Refresh token inválido o expirado.');

/**
 * Sesiones por dispositivo con rotación de refresh token y detección de
 * reutilización (si se presenta el token anterior, la sesión se revoca).
 */
@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    private readonly auditService: AuditService,
  ) {}

  async create(
    userId: string,
    deviceName: string,
    tx: Prisma.TransactionClient = this.prisma,
  ): Promise<CreatedSession> {
    const sessionId = randomUUID();
    const secret = this.tokens.generateRefreshSecret();
    const now = new Date();

    await tx.sessions.create({
      data: {
        id: sessionId,
        user_id: userId,
        device_name: deviceName,
        refresh_token_hash: this.tokens.hashRefreshSecret(secret),
        expires_at: new Date(now.getTime() + this.tokens.refreshTtlMs),
        last_used_at: now,
      },
    });

    return { sessionId, tokens: this.issue(userId, sessionId, secret) };
  }

  async rotate(
    refreshToken: string,
    client: ClientInfoData,
  ): Promise<TokenPairDto> {
    const parsed = this.tokens.parseRefreshToken(refreshToken);
    if (!parsed) throw invalidRefresh();

    const session = await this.prisma.sessions.findUnique({
      where: { id: parsed.sessionId },
      include: { user: { select: { deleted_at: true } } },
    });
    if (!session || session.revoked_at || session.user.deleted_at) {
      throw invalidRefresh();
    }

    const presented = this.tokens.hashRefreshSecret(parsed.secret);

    // Reutilización de un token ya rotado: posible robo, se revoca la sesión
    if (
      session.previous_refresh_token_hash &&
      this.tokens.safeEqual(presented, session.previous_refresh_token_hash)
    ) {
      await this.revoke(session.id, 'refresh_token_reuse');
      await this.auditService.recordSafely({
        userId: session.user_id,
        sessionId: session.id,
        event: AuditEvent.AuthRefreshReuse,
        outcome: 'failure',
        metadata: { action: 'session_revoked' },
        client,
      });
      throw invalidRefresh();
    }

    if (
      !this.tokens.safeEqual(presented, session.refresh_token_hash) ||
      session.expires_at <= new Date()
    ) {
      throw invalidRefresh();
    }

    const newSecret = this.tokens.generateRefreshSecret();
    const now = new Date();

    // Condición sobre el hash actual: si dos peticiones rotan a la vez, solo una gana
    const { count } = await this.prisma.sessions.updateMany({
      where: {
        id: session.id,
        refresh_token_hash: session.refresh_token_hash,
        revoked_at: null,
      },
      data: {
        refresh_token_hash: this.tokens.hashRefreshSecret(newSecret),
        previous_refresh_token_hash: session.refresh_token_hash,
        last_used_at: now,
        expires_at: new Date(now.getTime() + this.tokens.refreshTtlMs),
      },
    });
    if (count !== 1) throw invalidRefresh();

    return this.issue(session.user_id, session.id, newSecret);
  }

  async revoke(
    sessionId: string,
    reason: SessionRevokeReason,
    userId?: string,
  ): Promise<void> {
    await this.prisma.sessions.updateMany({
      where: {
        id: sessionId,
        revoked_at: null,
        ...(userId ? { user_id: userId } : {}),
      },
      data: { revoked_at: new Date(), revoke_reason: reason },
    });
  }

  async isActive(sessionId: string, userId: string): Promise<boolean> {
    const session = await this.prisma.sessions.findFirst({
      where: {
        id: sessionId,
        user_id: userId,
        revoked_at: null,
        expires_at: { gt: new Date() },
        user: { deleted_at: null },
      },
      select: { id: true },
    });
    return session !== null;
  }

  private issue(
    userId: string,
    sessionId: string,
    secret: string,
  ): TokenPairDto {
    return {
      tokenType: 'Bearer',
      accessToken: this.tokens.signAccessToken(userId, sessionId),
      expiresIn: this.tokens.accessTtlSeconds,
      refreshToken: this.tokens.buildRefreshToken(sessionId, secret),
    };
  }
}
