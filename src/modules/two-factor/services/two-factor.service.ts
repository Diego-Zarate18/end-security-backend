import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, two_factor } from '@prisma/client';
import { createHmac, randomInt, timingSafeEqual } from 'crypto';
import { generateSecret, generateURI, verify } from 'otplib';
import { toDataURL } from 'qrcode';
import type { ClientInfoData } from '../../../common/decorators';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { verifyAuthHash } from '../../auth/auth-hash';
import { TokenType } from '../../auth/auth.constants';
import { AuthResponseDto } from '../../auth/dto';
import { AuthService, TokenService } from '../../auth/services';
import { UsersService } from '../../users/services';
import {
  RecoveryCodesDto,
  SensitiveTwoFactorDto,
  TwoFactorSetupDto,
  TwoFactorStatusDto,
  VerifyTwoFactorDto,
} from '../dto';
import { TotpSecretService } from './totp-secret.service';

export interface TwoFactorActor {
  userId: string;
  sessionId: string;
  client: ClientInfoData;
}

const RECOVERY_CODE_COUNT = 10;
const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const MAX_FAILURES = 5;
const LOCK_MINUTES = 15;
/** ±30 s: tolera un paso de desfase en el reloj del teléfono. */
const EPOCH_TOLERANCE_SECONDS = 30;

/**
 * Verificación en dos pasos con TOTP (RFC 6238) y códigos de recuperación.
 *
 * - El secreto se guarda cifrado (AES-256-GCM, TotpSecretService).
 * - Un código TOTP no se acepta dos veces (`last_used_step`).
 * - Los códigos de recuperación son de un solo uso y solo se guarda su HMAC.
 * - 5 fallos en 15 minutos bloquean temporalmente todas las operaciones 2FA.
 */
@Injectable()
export class TwoFactorService {
  private readonly issuer: string;
  private readonly pepper: Buffer;
  /** jti de desafíos 2FA ya canjeados → vencimiento (ms). */
  private readonly usedChallenges = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
    private readonly auditService: AuditService,
    private readonly secrets: TotpSecretService,
    configService: ConfigService,
  ) {
    this.issuer = configService.get<string>('TOTP_APP_NAME') ?? 'End Security';
    this.pepper = Buffer.from(
      configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      'utf8',
    );
  }

  async status(userId: string): Promise<TwoFactorStatusDto> {
    const record = await this.prisma.two_factor.findUnique({
      where: { user_id: userId },
    });
    const recoveryCodesRemaining = await this.prisma.recovery_codes.count({
      where: { user_id: userId, used_at: null },
    });
    return {
      status: (record?.status as 'pending' | 'active') ?? 'disabled',
      activatedAt: record?.activated_at ?? null,
      recoveryCodesRemaining:
        record?.status === 'active' ? recoveryCodesRemaining : 0,
    };
  }

  /** Paso 1: genera el secreto (queda `pending` hasta confirmar un código). */
  async setup(
    actor: TwoFactorActor,
    authHash: string,
  ): Promise<TwoFactorSetupDto> {
    const user = await this.usersService.findActiveById(actor.userId);
    await this.ensureNotLocked(actor.userId);
    await this.reauthenticate(
      actor,
      user.auth_hash,
      authHash,
      AuditEvent.TwoFactorSetup,
    );

    if (user.two_factor?.status === 'active') {
      throw new ConflictException(
        'La verificación en dos pasos ya está activa. Desactívala para configurarla de nuevo.',
      );
    }

    const secret = generateSecret();
    const encrypted = this.secrets.encrypt(secret, user.id);
    const data = {
      status: 'pending',
      secret_ciphertext: encrypted.ciphertext,
      secret_nonce: encrypted.nonce,
      server_key_id: encrypted.keyId,
      last_used_step: null,
      activated_at: null,
    };
    await this.prisma.two_factor.upsert({
      where: { user_id: user.id },
      create: { user_id: user.id, ...data },
      update: { ...data, created_at: new Date() },
    });
    await this.audit(actor, AuditEvent.TwoFactorSetup, 'success');

    const otpauthUrl = generateURI({
      issuer: this.issuer,
      label: user.email,
      secret,
    });
    return {
      secret,
      otpauthUrl,
      qrCodeDataUrl: await toDataURL(otpauthUrl),
    };
  }

  /** Paso 2: el usuario demuestra que su app genera códigos válidos. */
  async activate(
    actor: TwoFactorActor,
    code: string,
  ): Promise<RecoveryCodesDto> {
    const record = await this.prisma.two_factor.findUnique({
      where: { user_id: actor.userId },
    });
    if (!record || record.status !== 'pending') {
      throw new BadRequestException(
        'Primero configura la verificación en dos pasos (/auth/2fa/setup).',
      );
    }
    await this.ensureNotLocked(actor.userId);

    const step = await this.consumeTotp(record, code);
    if (step === null) {
      await this.audit(
        actor,
        AuditEvent.TwoFactorActivate,
        'failure',
        'invalid_code',
      );
      throw this.invalidCode();
    }

    const recoveryCodes = this.generateRecoveryCodes();
    await this.prisma.$transaction(async (tx) => {
      await tx.two_factor.update({
        where: { user_id: actor.userId },
        data: { status: 'active', activated_at: new Date() },
      });
      await this.replaceRecoveryCodes(tx, actor.userId, recoveryCodes);
      await this.auditService.record(
        {
          userId: actor.userId,
          sessionId: actor.sessionId,
          event: AuditEvent.TwoFactorActivate,
          outcome: 'success',
          client: actor.client,
        },
        tx,
      );
    });
    return { recoveryCodes };
  }

  /** Segundo paso del login: canjea el challengeToken por la sesión. */
  async verifyLogin(
    dto: VerifyTwoFactorDto,
    client: ClientInfoData,
  ): Promise<AuthResponseDto> {
    if (!dto.code === !dto.recoveryCode) {
      throw new BadRequestException(
        'Envía code (6 dígitos) o recoveryCode, pero no ambos.',
      );
    }
    const claims = this.tokenService.verifyChallenge(
      dto.challengeToken,
      TokenType.TwoFactorPending,
    );
    const user = await this.usersService.findActiveById(claims.userId);
    if (user.two_factor?.status !== 'active') {
      throw new UnauthorizedException(
        'El desafío no es válido o ya venció. Inicia sesión de nuevo.',
      );
    }
    await this.ensureNotLocked(user.id);

    // Cada desafío abre una sola sesión. Se reserva antes del primer await para
    // que dos peticiones simultáneas con el mismo desafío no pasen ambas.
    const challengeId = claims.jti ?? '';
    if (!challengeId || this.usedChallenges.has(challengeId)) {
      throw new UnauthorizedException(
        'El desafío no es válido o ya venció. Inicia sesión de nuevo.',
      );
    }
    this.reserveChallenge(challengeId, claims.expiresAt);

    try {
      const record = await this.prisma.two_factor.findUniqueOrThrow({
        where: { user_id: user.id },
      });
      const method = dto.code ? 'totp' : 'recovery_code';
      const ok = dto.code
        ? (await this.consumeTotp(record, dto.code)) !== null
        : await this.consumeRecoveryCode(user.id, dto.recoveryCode!);

      const auditBase = { userId: user.id, client };
      if (!ok) {
        await this.auditService.recordSafely({
          ...auditBase,
          event: AuditEvent.TwoFactorVerify,
          outcome: 'failure',
          metadata: { method, reason: 'invalid_code' },
        });
        throw this.invalidCode();
      }

      const remaining = await this.prisma.recovery_codes.count({
        where: { user_id: user.id, used_at: null },
      });
      await this.auditService.record({
        ...auditBase,
        event: AuditEvent.TwoFactorVerify,
        outcome: 'success',
        metadata: { method, recoveryCodesRemaining: remaining },
      });
      return await this.authService.startSession(
        user,
        claims.deviceName,
        client,
      );
    } catch (error) {
      // Un código mal escrito no quema el desafío: se puede reintentar
      this.usedChallenges.delete(challengeId);
      throw error;
    }
  }

  /** Marca un desafío como usado hasta que venza; limpia los ya vencidos. */
  private reserveChallenge(id: string, expiresAt: number): void {
    const now = Date.now();
    for (const [key, exp] of this.usedChallenges) {
      if (exp <= now) this.usedChallenges.delete(key);
    }
    this.usedChallenges.set(id, expiresAt);
  }

  /** Desactivar exige contraseña maestra y un código vigente (TOTP o de recuperación). */
  async disable(
    actor: TwoFactorActor,
    dto: SensitiveTwoFactorDto,
  ): Promise<TwoFactorStatusDto> {
    await this.checkSensitive(actor, dto, AuditEvent.TwoFactorDisable);
    await this.prisma.$transaction(async (tx) => {
      await tx.recovery_codes.deleteMany({ where: { user_id: actor.userId } });
      await tx.two_factor.delete({ where: { user_id: actor.userId } });
      await this.auditService.record(
        {
          userId: actor.userId,
          sessionId: actor.sessionId,
          event: AuditEvent.TwoFactorDisable,
          outcome: 'success',
          client: actor.client,
        },
        tx,
      );
    });
    return this.status(actor.userId);
  }

  /** Invalida los códigos de recuperación anteriores y entrega 10 nuevos. */
  async regenerateRecoveryCodes(
    actor: TwoFactorActor,
    dto: SensitiveTwoFactorDto,
  ): Promise<RecoveryCodesDto> {
    await this.checkSensitive(
      actor,
      dto,
      AuditEvent.TwoFactorRecoveryRegenerate,
    );
    const recoveryCodes = this.generateRecoveryCodes();
    await this.prisma.$transaction(async (tx) => {
      await this.replaceRecoveryCodes(tx, actor.userId, recoveryCodes);
      await this.auditService.record(
        {
          userId: actor.userId,
          sessionId: actor.sessionId,
          event: AuditEvent.TwoFactorRecoveryRegenerate,
          outcome: 'success',
          client: actor.client,
        },
        tx,
      );
    });
    return { recoveryCodes };
  }

  private async checkSensitive(
    actor: TwoFactorActor,
    dto: SensitiveTwoFactorDto,
    event: AuditEvent,
  ): Promise<void> {
    const user = await this.usersService.findActiveById(actor.userId);
    if (user.two_factor?.status !== 'active') {
      throw new BadRequestException(
        'La verificación en dos pasos no está activa.',
      );
    }
    await this.ensureNotLocked(actor.userId);
    await this.reauthenticate(actor, user.auth_hash, dto.authHash, event);

    const record = await this.prisma.two_factor.findUniqueOrThrow({
      where: { user_id: actor.userId },
    });
    const ok = /^\d{6}$/.test(dto.code)
      ? (await this.consumeTotp(record, dto.code)) !== null
      : await this.consumeRecoveryCode(actor.userId, dto.code);
    if (!ok) {
      await this.audit(actor, event, 'failure', 'invalid_code');
      throw this.invalidCode();
    }
  }

  private async reauthenticate(
    actor: TwoFactorActor,
    storedHash: string,
    authHash: string,
    event: AuditEvent,
  ): Promise<void> {
    if (!(await verifyAuthHash(storedHash, authHash))) {
      await this.audit(actor, event, 'failure', 'invalid_credentials');
      // 403 y no 401: la sesión sigue siendo válida
      throw new ForbiddenException('La contraseña maestra no es correcta.');
    }
  }

  /**
   * Valida el código y marca su paso de tiempo como usado en un solo UPDATE
   * condicionado: el mismo código no sirve dos veces, ni en paralelo.
   */
  private async consumeTotp(
    record: two_factor,
    code: string,
  ): Promise<bigint | null> {
    const secret = this.secrets.decrypt(
      {
        ciphertext: record.secret_ciphertext,
        nonce: record.secret_nonce,
        keyId: record.server_key_id,
      },
      record.user_id,
    );
    const result = await verify({
      secret,
      token: code,
      epochTolerance: EPOCH_TOLERANCE_SECONDS,
      ...(record.last_used_step !== null
        ? { afterTimeStep: Number(record.last_used_step) }
        : {}),
    });
    if (!result.valid || !('timeStep' in result)) return null;

    const step = BigInt(result.timeStep);
    const { count } = await this.prisma.two_factor.updateMany({
      where: {
        user_id: record.user_id,
        OR: [{ last_used_step: null }, { last_used_step: { lt: step } }],
      },
      data: { last_used_step: step },
    });
    return count === 1 ? step : null;
  }

  private async consumeRecoveryCode(
    userId: string,
    code: string,
  ): Promise<boolean> {
    const expected = this.hashRecoveryCode(userId, code);
    const unused = await this.prisma.recovery_codes.findMany({
      where: { user_id: userId, used_at: null },
      select: { id: true, code_hash: true },
    });
    // Se comparan todos para no filtrar por tiempo cuál coincidió
    let matchId: string | null = null;
    for (const candidate of unused) {
      const same =
        candidate.code_hash.length === expected.length &&
        timingSafeEqual(candidate.code_hash, expected);
      if (same) matchId = candidate.id;
    }
    if (!matchId) return false;

    const { count } = await this.prisma.recovery_codes.updateMany({
      where: { id: matchId, used_at: null },
      data: { used_at: new Date() },
    });
    return count === 1;
  }

  private async replaceRecoveryCodes(
    tx: Prisma.TransactionClient,
    userId: string,
    codes: string[],
  ): Promise<void> {
    await tx.recovery_codes.deleteMany({ where: { user_id: userId } });
    await tx.recovery_codes.createMany({
      data: codes.map((code) => ({
        user_id: userId,
        code_hash: this.hashRecoveryCode(userId, code),
      })),
    });
  }

  private generateRecoveryCodes(): string[] {
    return Array.from({ length: RECOVERY_CODE_COUNT }, () => {
      const chars = Array.from(
        { length: 10 },
        () => RECOVERY_ALPHABET[randomInt(RECOVERY_ALPHABET.length)],
      ).join('');
      return `${chars.slice(0, 5)}-${chars.slice(5)}`;
    });
  }

  private hashRecoveryCode(
    userId: string,
    code: string,
  ): Uint8Array<ArrayBuffer> {
    const normalized = code.toLowerCase().replace('-', '');
    const digest = createHmac('sha256', this.pepper)
      .update(`recovery-code:${userId}:${normalized}`)
      .digest();
    const out = new Uint8Array(digest.length);
    out.set(digest);
    return out;
  }

  /** 5 fallos de 2FA en 15 minutos bloquean temporalmente estas operaciones. */
  private async ensureNotLocked(userId: string): Promise<void> {
    const failures = await this.prisma.audit_log.count({
      where: {
        user_id: userId,
        event_type: { startsWith: '2fa.' },
        outcome: 'failure',
        occurred_at: { gte: new Date(Date.now() - LOCK_MINUTES * 60_000) },
      },
    });
    if (failures >= MAX_FAILURES) {
      throw new HttpException(
        {
          error: 'TooManyRequests',
          message: `Demasiados intentos fallidos. Espera ${LOCK_MINUTES} minutos.`,
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private invalidCode() {
    return new UnauthorizedException({
      error: 'InvalidSecondFactor',
      message: 'El código de verificación no es válido.',
    });
  }

  private audit(
    actor: TwoFactorActor,
    event: AuditEvent,
    outcome: 'success' | 'failure',
    reason?: string,
  ): Promise<void> {
    const input = {
      userId: actor.userId,
      sessionId: actor.sessionId,
      event,
      outcome,
      client: actor.client,
      ...(reason ? { metadata: { reason } } : {}),
    };
    return outcome === 'failure'
      ? this.auditService.recordSafely(input)
      : this.auditService.record(input);
  }
}
