import { BadRequestException, Injectable, Logger } from '@nestjs/common';
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
  MailService,
  passwordChangedMail,
} from '../../mail/services';
import { UsersService } from '../../users/services';
import { ReauthService } from './reauth.service';
import {
  ChangeMasterPasswordDto,
  DeleteAccountDto,
  PasswordChangedDto,
} from '../dto';

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
  ) {}

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
      const updated = await tx.users.update({
        where: { id: user.id },
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
