import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from '@nestjs/common';
import { email_verifications, Prisma } from '@prisma/client';
import { randomInt, randomUUID } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { AuthService } from '../../auth/auth.service';
import { TokenService } from '../../auth/services';
import { MailService } from '../../mail/mail.service';
import {
  emailChangedNoticeMail,
  maskEmail,
  verificationCodeMail,
} from '../../mail/mail.templates';
import { UserResponseDto } from '../../users/dto';
import { UsersService } from '../../users/users.service';
import { CodeSentDto, RequestEmailChangeDto } from '../dto';

type Purpose = 'verify_email' | 'change_email';

export const CODE_TTL_MINUTES = 15;
export const MAX_ATTEMPTS = 5;
export const RESEND_COOLDOWN_SECONDS = 60;

const REQUEST_EVENT: Record<Purpose, AuditEvent> = {
  verify_email: AuditEvent.EmailVerifyRequest,
  change_email: AuditEvent.EmailChangeRequest,
};
const CONFIRM_EVENT: Record<Purpose, AuditEvent> = {
  verify_email: AuditEvent.EmailVerifyConfirm,
  change_email: AuditEvent.EmailChangeConfirm,
};

const invalidCode = () =>
  new BadRequestException({
    error: 'InvalidCode',
    message: 'El código es inválido o ya venció. Solicita uno nuevo.',
    details: { remainingAttempts: 0 },
  });

interface Actor {
  userId: string;
  sessionId: string;
  client: ClientInfoData;
}

/**
 * Códigos de un solo uso por correo (tabla email_verifications):
 * 6 dígitos, 15 minutos de vigencia, 5 intentos y 60 s entre envíos. En la BD
 * solo queda el HMAC del código; un código nuevo invalida los anteriores.
 */
@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
  ) {}

  async requestVerification(actor: Actor): Promise<CodeSentDto> {
    const user = await this.usersService.findActiveById(actor.userId);
    if (user.email_verified_at) {
      throw new ConflictException('Tu correo ya está verificado.');
    }
    return this.issueCode(actor, 'verify_email', user.email);
  }

  async confirmVerification(
    actor: Actor,
    code: string,
  ): Promise<UserResponseDto> {
    const entry = await this.checkCode(actor, 'verify_email', code);
    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await this.consume(tx, entry.id, now);
      await tx.users.update({
        where: { id: actor.userId },
        data: { email_verified_at: now },
      });
      await this.auditService.record(
        {
          userId: actor.userId,
          sessionId: actor.sessionId,
          event: AuditEvent.EmailVerifyConfirm,
          outcome: 'success',
          client: actor.client,
        },
        tx,
      );
    });

    return this.usersService.getProfile(actor.userId);
  }

  async requestEmailChange(
    actor: Actor,
    dto: RequestEmailChangeDto,
  ): Promise<CodeSentDto> {
    const user = await this.usersService.findActiveById(actor.userId);

    if (!(await this.authService.verifyAuthHash(user, dto.authHash))) {
      await this.auditService.recordSafely({
        userId: actor.userId,
        sessionId: actor.sessionId,
        event: AuditEvent.EmailChangeRequest,
        outcome: 'failure',
        metadata: { reason: 'invalid_credentials' },
        client: actor.client,
      });
      // 403 y no 401: la sesión sigue siendo válida, solo falló la reautenticación
      throw new ForbiddenException('La contraseña maestra no es correcta.');
    }

    if (dto.newEmail === user.email) {
      throw new BadRequestException('El nuevo correo es igual al actual.');
    }

    // Si el correo ya es de otra cuenta se responde igual, pero sin enviar nada,
    // para no revelar qué correos están registrados.
    if (await this.usersService.findByEmail(dto.newEmail)) {
      await this.auditService.record({
        userId: actor.userId,
        sessionId: actor.sessionId,
        event: AuditEvent.EmailChangeRequest,
        outcome: 'failure',
        metadata: { reason: 'email_unavailable' },
        client: actor.client,
      });
      return {
        sentTo: maskEmail(dto.newEmail),
        expiresAt: new Date(Date.now() + CODE_TTL_MINUTES * 60_000),
        resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
      };
    }

    return this.issueCode(actor, 'change_email', dto.newEmail);
  }

  async confirmEmailChange(
    actor: Actor,
    code: string,
  ): Promise<UserResponseDto> {
    const entry = await this.checkCode(actor, 'change_email', code);
    const previous = await this.usersService.findActiveById(actor.userId);
    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await this.consume(tx, entry.id, now);

      const taken = await tx.users.findUnique({
        where: { email: entry.target_email },
        select: { id: true },
      });
      if (taken) {
        throw new ConflictException('Ese correo ya no está disponible.');
      }

      await tx.users.update({
        where: { id: actor.userId },
        data: { email: entry.target_email, email_verified_at: now },
      });

      // Cerrar los demás dispositivos: si alguien más tenía sesión, la pierde
      const { count } = await tx.sessions.updateMany({
        where: {
          user_id: actor.userId,
          revoked_at: null,
          id: { not: actor.sessionId },
        },
        data: { revoked_at: now, revoke_reason: 'email_change' },
      });

      // Cualquier otro código abierto deja de servir
      await tx.email_verifications.updateMany({
        where: {
          user_id: actor.userId,
          consumed_at: null,
          expires_at: { gt: now },
        },
        data: { expires_at: now },
      });

      await this.auditService.record(
        {
          userId: actor.userId,
          sessionId: actor.sessionId,
          event: AuditEvent.EmailChangeConfirm,
          outcome: 'success',
          metadata: { otherSessionsRevoked: count },
          client: actor.client,
        },
        tx,
      );
    });

    // Aviso al correo anterior; si falla, el cambio ya está hecho
    try {
      await this.mailService.send({
        to: previous.email,
        ...emailChangedNoticeMail(entry.target_email),
        idempotencyKey: `email-changed/${entry.id}`,
      });
    } catch {
      this.logger.warn('No se pudo enviar el aviso al correo anterior.');
    }

    return this.usersService.getProfile(actor.userId);
  }

  private async issueCode(
    actor: Actor,
    purpose: Purpose,
    target: string,
  ): Promise<CodeSentDto> {
    const now = new Date();
    const latest = await this.prisma.email_verifications.findFirst({
      where: { user_id: actor.userId, purpose },
      orderBy: { created_at: 'desc' },
      select: { created_at: true },
    });
    if (latest) {
      const waited = Math.floor(
        (now.getTime() - latest.created_at.getTime()) / 1000,
      );
      if (waited < RESEND_COOLDOWN_SECONDS) {
        const retryAfterSeconds = RESEND_COOLDOWN_SECONDS - waited;
        throw new HttpException(
          {
            error: 'TooManyRequests',
            message: `Espera ${retryAfterSeconds} segundos antes de pedir otro código.`,
            details: { retryAfterSeconds },
          },
          HttpStatus.TOO_MANY_REQUESTS,
        );
      }
    }

    const id = randomUUID();
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const expiresAt = new Date(now.getTime() + CODE_TTL_MINUTES * 60_000);

    await this.prisma.$transaction([
      this.prisma.email_verifications.updateMany({
        where: {
          user_id: actor.userId,
          purpose,
          consumed_at: null,
          expires_at: { gt: now },
        },
        data: { expires_at: now },
      }),
      this.prisma.email_verifications.create({
        data: {
          id,
          user_id: actor.userId,
          purpose,
          target_email: target,
          code_hash: this.tokenService.hashEmailCode(id, code),
          attempts: 0,
          expires_at: expiresAt,
        },
      }),
    ]);

    try {
      await this.mailService.send({
        to: target,
        ...verificationCodeMail(code, CODE_TTL_MINUTES, purpose),
        idempotencyKey: `${purpose}/${id}`,
      });
    } catch (error) {
      // Un código que nunca llegó no debe quedar vigente
      await this.prisma.email_verifications.update({
        where: { id },
        data: { expires_at: new Date() },
      });
      await this.auditService.recordSafely({
        userId: actor.userId,
        sessionId: actor.sessionId,
        event: REQUEST_EVENT[purpose],
        outcome: 'failure',
        metadata: { reason: 'mail_send_failed' },
        client: actor.client,
      });
      throw error;
    }

    await this.auditService.record({
      userId: actor.userId,
      sessionId: actor.sessionId,
      event: REQUEST_EVENT[purpose],
      outcome: 'success',
      client: actor.client,
    });

    return {
      sentTo: maskEmail(target),
      expiresAt,
      resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
    };
  }

  /**
   * Gasta un intento ANTES de comparar, con un UPDATE condicionado: así ni
   * peticiones en paralelo pueden superar los 5 intentos.
   */
  private async checkCode(
    actor: Actor,
    purpose: Purpose,
    code: string,
  ): Promise<email_verifications> {
    const entry = await this.prisma.email_verifications.findFirst({
      where: {
        user_id: actor.userId,
        purpose,
        consumed_at: null,
        expires_at: { gt: new Date() },
      },
      orderBy: { created_at: 'desc' },
    });
    if (!entry) throw invalidCode();

    const { count } = await this.prisma.email_verifications.updateMany({
      where: {
        id: entry.id,
        consumed_at: null,
        attempts: { lt: MAX_ATTEMPTS },
      },
      data: { attempts: { increment: 1 } },
    });
    if (count === 0) throw invalidCode();

    const matches = this.tokenService.safeEqual(
      this.tokenService.hashEmailCode(entry.id, code),
      entry.code_hash,
    );
    if (!matches) {
      const remainingAttempts = Math.max(0, MAX_ATTEMPTS - entry.attempts - 1);
      await this.auditService.recordSafely({
        userId: actor.userId,
        sessionId: actor.sessionId,
        event: CONFIRM_EVENT[purpose],
        outcome: 'failure',
        metadata: { remainingAttempts },
        client: actor.client,
      });
      throw new BadRequestException({
        error: 'InvalidCode',
        message:
          remainingAttempts > 0
            ? 'Código incorrecto.'
            : 'Código incorrecto. Agotaste los intentos; solicita un código nuevo.',
        details: { remainingAttempts },
      });
    }

    return entry;
  }

  private async consume(
    tx: Prisma.TransactionClient,
    id: string,
    now: Date,
  ): Promise<void> {
    const { count } = await tx.email_verifications.updateMany({
      where: { id, consumed_at: null },
      data: { consumed_at: now },
    });
    if (count !== 1) throw invalidCode();
  }
}
