import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { ClientInfoData } from '../../../common/decorators';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { verifyAuthHash } from '../../auth/auth-hash';
import { TwoFactorService } from '../../two-factor/services';
import { UserWithTwoFactor } from '../../users/services';

export interface ReauthActor {
  userId: string;
  sessionId: string;
  client: ClientInfoData;
}

/**
 * Reautenticación para operaciones irreversibles: contraseña maestra y, si la
 * cuenta tiene 2FA activo, un código TOTP o de recuperación. Los fallos quedan
 * en auditoría con el evento de la operación.
 */
@Injectable()
export class ReauthService {
  constructor(
    private readonly twoFactor: TwoFactorService,
    private readonly auditService: AuditService,
  ) {}

  async verify(
    actor: ReauthActor,
    user: UserWithTwoFactor,
    authHash: string,
    code: string | undefined,
    event: AuditEvent,
  ): Promise<void> {
    if (!(await verifyAuthHash(user.auth_hash, authHash))) {
      await this.auditService.recordSafely({
        userId: user.id,
        sessionId: actor.sessionId,
        event,
        outcome: 'failure',
        metadata: { reason: 'invalid_credentials' },
        client: actor.client,
      });
      // 403 y no 401: la sesión sigue siendo válida
      throw new ForbiddenException('La contraseña maestra no es correcta.');
    }

    if (user.two_factor?.status !== 'active') return;
    if (!code) {
      throw new BadRequestException({
        error: 'SecondFactorRequired',
        message:
          'Tu cuenta tiene verificación en dos pasos: envía también code (de tu app o de recuperación).',
      });
    }
    await this.twoFactor.verifySecondFactor(actor, code, event);
  }
}
