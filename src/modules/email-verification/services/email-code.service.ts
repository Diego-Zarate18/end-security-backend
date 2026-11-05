import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { email_verifications, Prisma } from '@prisma/client';
import { createHmac, randomInt, randomUUID, timingSafeEqual } from 'crypto';
import type { ClientInfoData } from '../../../common/decorators';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { MailService } from '../../mail/services/mail.service';
import {
  maskEmail,
  verificationCodeMail,
} from '../../mail/services/mail.templates';
import { CodeSentDto } from '../dto';

export type EmailCodePurpose = 'verify_email' | 'change_email';

export const CODE_TTL_MINUTES = 15;
export const MAX_ATTEMPTS = 5;
export const RESEND_COOLDOWN_SECONDS = 60;

const REQUEST_EVENT: Record<EmailCodePurpose, AuditEvent> = {
  verify_email: AuditEvent.EmailVerifyRequest,
  change_email: AuditEvent.EmailChangeRequest,
};
const CONFIRM_EVENT: Record<EmailCodePurpose, AuditEvent> = {
  verify_email: AuditEvent.EmailVerifyConfirm,
  change_email: AuditEvent.EmailChangeConfirm,
};

export interface EmailCodeActor {
  userId: string;
  sessionId?: string | null;
  client: ClientInfoData;
}

export const invalidEmailCode = () =>
  new BadRequestException({
    error: 'InvalidCode',
    message: 'El código es inválido o ya venció. Solicita uno nuevo.',
    details: { remainingAttempts: 0 },
  });

/**
 * Códigos de un solo uso por correo (tabla email_verifications):
 * 6 dígitos, 15 minutos de vigencia, 5 intentos y 60 s entre envíos. En la BD
 * solo queda su HMAC con un pepper del servidor; un código nuevo invalida los
 * anteriores del mismo propósito.
 */
@Injectable()
export class EmailCodeService {
  private readonly pepper: Buffer;

  constructor(
    private readonly prisma: PrismaService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
    configService: ConfigService,
  ) {
    this.pepper = Buffer.from(
      configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      'utf8',
    );
  }

  /**
   * Genera y envía un código. Con `onCooldown: 'skip'` no falla si se pidió
   * uno hace menos de 60 s: responde `codeSent: false` y el anterior sigue vigente.
   */
  async issue(
    actor: EmailCodeActor,
    purpose: EmailCodePurpose,
    target: string,
    onCooldown: 'throw' | 'skip' = 'throw',
  ): Promise<CodeSentDto> {
    const now = new Date();
    const latest = await this.prisma.email_verifications.findFirst({
      where: { user_id: actor.userId, purpose },
      orderBy: { created_at: 'desc' },
      select: { created_at: true, expires_at: true },
    });
    if (latest) {
      const waited = Math.floor(
        (now.getTime() - latest.created_at.getTime()) / 1000,
      );
      if (waited < RESEND_COOLDOWN_SECONDS) {
        const retryAfterSeconds = RESEND_COOLDOWN_SECONDS - waited;
        if (onCooldown === 'skip') {
          return {
            sentTo: maskEmail(target),
            codeSent: false,
            expiresAt: latest.expires_at,
            resendAvailableInSeconds: retryAfterSeconds,
          };
        }
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
          code_hash: this.hash(id, code),
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
      codeSent: true,
      expiresAt,
      resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
    };
  }

  /**
   * Gasta un intento ANTES de comparar, con un UPDATE condicionado: ni
   * peticiones en paralelo pueden superar los 5 intentos.
   */
  async check(
    actor: EmailCodeActor,
    purpose: EmailCodePurpose,
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
    if (!entry) throw invalidEmailCode();

    const { count } = await this.prisma.email_verifications.updateMany({
      where: {
        id: entry.id,
        consumed_at: null,
        attempts: { lt: MAX_ATTEMPTS },
      },
      data: { attempts: { increment: 1 } },
    });
    if (count === 0) throw invalidEmailCode();

    const expected = this.hash(entry.id, code);
    const matches =
      expected.length === entry.code_hash.length &&
      timingSafeEqual(expected, entry.code_hash);
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

  /** Marca el código como usado dentro de la transacción del negocio. */
  async consume(
    tx: Prisma.TransactionClient,
    id: string,
    now: Date,
  ): Promise<void> {
    const { count } = await tx.email_verifications.updateMany({
      where: { id, consumed_at: null },
      data: { consumed_at: now },
    });
    if (count !== 1) throw invalidEmailCode();
  }

  /** HMAC ligado al registro: un volcado de la BD no permite probar los 10^6 códigos. */
  private hash(verificationId: string, code: string): Uint8Array<ArrayBuffer> {
    const digest = createHmac('sha256', this.pepper)
      .update(`email-code:${verificationId}:${code}`)
      .digest();
    const out = new Uint8Array(digest.length);
    out.set(digest);
    return out;
  }
}
