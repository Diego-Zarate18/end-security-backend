import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma.service';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { verifyAuthHash } from '../../auth/auth-hash';
import { MailService } from '../../mail/services/mail.service';
import {
  emailChangedNoticeMail,
  maskEmail,
} from '../../mail/services/mail.templates';
import { UserResponseDto } from '../../users/dto';
import { UsersService } from '../../users/services/users.service';
import { CodeSentDto, RequestEmailChangeDto } from '../dto';
import {
  CODE_TTL_MINUTES,
  EmailCodeActor,
  EmailCodeService,
  RESEND_COOLDOWN_SECONDS,
} from './email-code.service';

interface SessionActor extends EmailCodeActor {
  sessionId: string;
}

/**
 * Cambio del correo de la cuenta (usuario ya autenticado). La verificación
 * inicial del correo es parte del inicio de sesión y vive en AuthService.
 */
@Injectable()
export class EmailVerificationService {
  private readonly logger = new Logger(EmailVerificationService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly usersService: UsersService,
    private readonly emailCodes: EmailCodeService,
    private readonly mailService: MailService,
    private readonly auditService: AuditService,
  ) {}

  async requestEmailChange(
    actor: SessionActor,
    dto: RequestEmailChangeDto,
  ): Promise<CodeSentDto> {
    const user = await this.usersService.findActiveById(actor.userId);

    if (!(await verifyAuthHash(user.auth_hash, dto.authHash))) {
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
        codeSent: true,
        expiresAt: new Date(Date.now() + CODE_TTL_MINUTES * 60_000),
        resendAvailableInSeconds: RESEND_COOLDOWN_SECONDS,
      };
    }

    return this.emailCodes.issue(actor, 'change_email', dto.newEmail);
  }

  async confirmEmailChange(
    actor: SessionActor,
    code: string,
  ): Promise<UserResponseDto> {
    const entry = await this.emailCodes.check(actor, 'change_email', code);
    const previous = await this.usersService.findActiveById(actor.userId);
    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await this.emailCodes.consume(tx, entry.id, now);

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
}
