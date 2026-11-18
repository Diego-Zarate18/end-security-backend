import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import * as argon2 from 'argon2';
import { randomUUID } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { fromBase64 } from '../../../common/utils';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { verifyAuthHash } from '../../auth/auth-hash';
import { SERVER_ARGON2_OPTIONS } from '../../auth/auth.constants';
import {
  accountDeletedMail,
  emailChangedMail,
  emailChangeRequestedMail,
  MailService,
  maskEmail,
  passwordChangedMail,
} from '../../mail/services';
import {
  EmailCodeService,
  invalidEmailCode,
} from '../../email-verification/services';
import { CodeSentDto } from '../../email-verification/dto';
import { UserResponseDto } from '../../users/dto';
import { UsersService } from '../../users/services';
import { ReauthService } from './reauth.service';
import {
  ChangeMasterPasswordDto,
  ConfirmEmailChangeDto,
  DeleteAccountDto,
  PasswordChangedDto,
  RequestEmailChangeDto,
} from '../dto';

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
/** DEC-63: solicitudes aceptadas por hora y por día; la espera tras un cambio es DAY_MS. */
const EMAIL_CHANGE_PER_HOUR = 3;
const EMAIL_CHANGE_PER_DAY = 5;

export interface AccountActor {
  userId: string;
  sessionId: string;
  client: ClientInfoData;
}

/**
 * Operaciones irreversibles sobre la cuenta. Ambas piden la contraseña maestra
 * y, si 2FA está activo, un código TOTP o de recuperación.
 */
@Injectable()
export class AccountService {
  private readonly logger = new Logger(AccountService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly reauth: ReauthService,
    private readonly auditService: AuditService,
    private readonly mailService: MailService,
    private readonly emailCodes: EmailCodeService,
  ) {}

  /**
   * Pide cambiar el correo (DEC-63): manda un código al correo nuevo y una
   * alerta al actual. Si el correo nuevo ya tiene cuenta responde igual, pero
   * el código no se envía a nadie y nunca se podrá confirmar.
   */
  async requestEmailChange(
    actor: AccountActor,
    dto: RequestEmailChangeDto,
  ): Promise<CodeSentDto> {
    const user = await this.usersService.findActiveById(actor.userId);
    if (dto.newEmail === user.email) {
      throw new BadRequestException(
        'El correo nuevo debe ser distinto del actual.',
      );
    }
    await this.reauth.verify(
      actor,
      user,
      dto.authHash,
      dto.code,
      AuditEvent.AccountEmailChange,
    );
    await this.ensureEmailChangeAllowed(user.id);

    const taken = await this.usersService.findByEmail(dto.newEmail);
    const sent = await this.emailCodes.issue(
      { userId: user.id, client: actor.client },
      dto.newEmail,
      { purpose: 'change_email', deliver: !taken },
    );
    await this.notify(
      user.email,
      emailChangeRequestedMail(maskEmail(dto.newEmail)),
      `email-change-request/${user.id}/${sent.expiresAt.getTime()}`,
    );
    return sent;
  }

  /** Confirma el código del correo nuevo y cambia el correo de la cuenta. */
  async confirmEmailChange(
    actor: AccountActor,
    dto: ConfirmEmailChangeDto,
  ): Promise<UserResponseDto> {
    const user = await this.usersService.findActiveById(actor.userId);
    const entry = await this.emailCodes.check(
      { userId: user.id, client: actor.client },
      dto.code,
      'change_email',
    );
    const now = new Date();

    await this.prisma
      .$transaction(async (tx) => {
        // INV-20: primero users, después email_verifications
        await tx.users.update({
          where: { id: user.id },
          data: { email: entry.target_email, email_verified_at: now },
        });
        await this.emailCodes.consume(tx, entry.id, now);
        await this.auditService.record(
          {
            userId: user.id,
            sessionId: actor.sessionId,
            event: AuditEvent.AccountEmailChange,
            outcome: 'success',
            client: actor.client,
          },
          tx,
        );
      })
      .catch((error: unknown) => {
        // El correo se ocupó entre la solicitud y la confirmación
        if (
          error instanceof Prisma.PrismaClientKnownRequestError &&
          error.code === 'P2002'
        ) {
          throw invalidEmailCode();
        }
        throw error;
      });

    await this.notify(
      user.email,
      emailChangedMail(maskEmail(entry.target_email)),
      `email-changed/${user.id}/${entry.id}`,
    );
    return this.usersService.getProfile(user.id);
  }

  /** Límites de DEC-63, contados en la BD; al pasarse, 429 con retryAfterSeconds. */
  private async ensureEmailChangeAllowed(userId: string): Promise<void> {
    const now = Date.now();
    const requests = await this.prisma.email_verifications.findMany({
      where: {
        user_id: userId,
        purpose: 'change_email',
        created_at: { gte: new Date(now - DAY_MS) },
      },
      orderBy: { created_at: 'asc' },
      select: { created_at: true },
    });
    const lastHour = requests.filter(
      (r) => r.created_at.getTime() > now - HOUR_MS,
    );
    const lastChange = await this.prisma.audit_log.findFirst({
      where: {
        user_id: userId,
        event_type: AuditEvent.AccountEmailChange,
        outcome: 'success',
        occurred_at: { gte: new Date(now - DAY_MS) },
      },
      orderBy: { id: 'desc' },
      select: { occurred_at: true },
    });
    const allowedAt = emailChangeAllowedAt(
      requests.map((r) => r.created_at.getTime()),
      lastHour.map((r) => r.created_at.getTime()),
      lastChange?.occurred_at.getTime() ?? null,
    );
    if (allowedAt > now) {
      const retryAfterSeconds = Math.ceil((allowedAt - now) / 1000);
      throw new HttpException(
        {
          error: 'TooManyRequests',
          message: 'Ya no puedes cambiar tu correo por ahora.',
          details: { retryAfterSeconds },
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  async changeMasterPassword(
    actor: AccountActor,
    dto: ChangeMasterPasswordDto,
  ): Promise<PasswordChangedDto> {
    const event = AuditEvent.AccountPasswordChange;
    const user = await this.usersService.findActiveById(actor.userId);
    await this.reauth.verify(actor, user, dto.currentAuthHash, dto.code, event);

    if (await verifyAuthHash(user.auth_hash, dto.newAuthHash)) {
      throw new BadRequestException(
        'La nueva contraseña maestra debe ser distinta de la actual.',
      );
    }

    // Defensa en profundidad, igual que en el registro
    const authHash = await argon2.hash(
      Buffer.from(fromBase64(dto.newAuthHash)),
      SERVER_ARGON2_OPTIONS,
    );

    const result = await this.prisma.$transaction(async (tx) => {
      // Con expectedKeyVersion, el UPDATE solo aplica si nadie cambió las llaves antes
      const updated = await tx.users
        .update({
          where: {
            id: user.id,
            ...(dto.expectedKeyVersion !== undefined
              ? { key_version: dto.expectedKeyVersion }
              : {}),
          },
          data: {
            auth_hash: authHash,
            kdf_salt: fromBase64(dto.kdf.salt),
            kdf_memory_kib: dto.kdf.memoryKib,
            kdf_iterations: dto.kdf.iterations,
            kdf_parallelism: dto.kdf.parallelism,
            pvk_ciphertext: fromBase64(dto.pvk.ciphertext),
            pvk_nonce: fromBase64(dto.pvk.nonce),
            key_version: { increment: 1 },
          },
          select: { key_version: true },
        })
        .catch(async (error: unknown) => {
          if (
            error instanceof Prisma.PrismaClientKnownRequestError &&
            error.code === 'P2025'
          ) {
            const current = await tx.users.findUniqueOrThrow({
              where: { id: user.id },
              select: { key_version: true },
            });
            throw new ConflictException({
              error: 'KeyVersionMismatch',
              message:
                'Las llaves de la cuenta cambiaron en otro dispositivo. Inicia sesión de nuevo y repite el cambio.',
              details: { currentKeyVersion: current.key_version },
            });
          }
          throw error;
        });

      // Quien tuviera la contraseña anterior pierde sus sesiones
      const { count } = await tx.sessions.updateMany({
        where: {
          user_id: user.id,
          revoked_at: null,
          id: { not: actor.sessionId },
        },
        data: { revoked_at: new Date(), revoke_reason: 'password_change' },
      });

      await this.auditService.record(
        {
          userId: user.id,
          sessionId: actor.sessionId,
          event,
          outcome: 'success',
          metadata: {
            keyVersion: updated.key_version,
            otherSessionsRevoked: count,
          },
          client: actor.client,
        },
        tx,
      );
      return { keyVersion: updated.key_version, otherSessionsRevoked: count };
    });

    await this.notify(
      user.email,
      passwordChangedMail(),
      `password-changed/${user.id}/${result.keyVersion}`,
    );
    return result;
  }

  /**
   * Borra la bóveda, el 2FA, las sesiones y los datos personales, y anonimiza
   * la fila del usuario. La fila se conserva solo para que la cadena de
   * auditoría siga siendo verificable; el correo queda libre para registrarse.
   */
  async deleteAccount(
    actor: AccountActor,
    dto: DeleteAccountDto,
  ): Promise<void> {
    const event = AuditEvent.AccountDelete;
    const user = await this.usersService.findActiveById(actor.userId);
    await this.reauth.verify(actor, user, dto.authHash, dto.code, event);

    const email = user.email;
    const now = new Date();
    const empty = new Uint8Array(0);

    await this.prisma.$transaction(async (tx) => {
      await this.auditService.record(
        {
          userId: user.id,
          sessionId: actor.sessionId,
          event,
          outcome: 'success',
          client: actor.client,
        },
        tx,
      );
      await tx.vault_items.deleteMany({ where: { user_id: user.id } });
      await tx.recovery_codes.deleteMany({ where: { user_id: user.id } });
      await tx.two_factor.deleteMany({ where: { user_id: user.id } });
      await tx.email_verifications.deleteMany({ where: { user_id: user.id } });
      // IP y User-Agent de todo su historial (la cadena no depende de ellos)
      await tx.audit_log_pii.deleteMany({
        where: { audit_log: { user_id: user.id } },
      });
      // Al borrar las sesiones, audit_log.session_id queda en NULL (no entra al HMAC)
      await tx.sessions.deleteMany({ where: { user_id: user.id } });
      await tx.users.update({
        where: { id: user.id },
        data: {
          email: `deleted+${randomUUID()}@deleted.invalid`,
          display_name: 'Cuenta eliminada',
          // No es un hash PHC válido: ningún login puede coincidir
          auth_hash: '!deleted',
          kdf_salt: empty,
          pvk_ciphertext: empty,
          pvk_nonce: empty,
          email_verified_at: null,
          deleted_at: now,
          anonymized_at: now,
        },
      });
    });

    await this.notify(
      email,
      accountDeletedMail(),
      `account-deleted/${user.id}`,
    );
  }

  /** Los avisos por correo nunca hacen fallar la operación ya hecha. */
  private async notify(
    to: string,
    mail: { subject: string; html: string; text: string },
    idempotencyKey: string,
  ): Promise<void> {
    try {
      await this.mailService.send({ to, ...mail, idempotencyKey });
    } catch {
      this.logger.warn(`No se pudo enviar el aviso: ${mail.subject}`);
    }
  }
}

/**
 * Momento (ms) desde el que se puede volver a pedir un cambio de correo.
 * `day` y `hour`: solicitudes de las últimas 24 h y 1 h, de la más vieja a la
 * más nueva; `lastChange`: último cambio completado en las últimas 24 h.
 */
export function emailChangeAllowedAt(
  day: number[],
  hour: number[],
  lastChange: number | null,
): number {
  return Math.max(
    hour.length >= EMAIL_CHANGE_PER_HOUR
      ? hour[hour.length - EMAIL_CHANGE_PER_HOUR] + HOUR_MS
      : 0,
    day.length >= EMAIL_CHANGE_PER_DAY
      ? day[day.length - EMAIL_CHANGE_PER_DAY] + DAY_MS
      : 0,
    lastChange !== null ? lastChange + DAY_MS : 0,
  );
}
