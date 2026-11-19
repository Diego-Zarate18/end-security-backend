import {
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Post,
} from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
} from '../../../common/decorators';
import { AuditEvent } from '../../audit/audit.constants';
import { AuditService } from '../../audit/services';
import { RevokedSessionsDto, SessionDto } from '../dto';
import { SessionsService } from '../services';
import type { AuthenticatedUser } from '../strategies';

/**
 * Dispositivos con sesión abierta. Cerrar sesiones no pide contraseña: es una
 * acción de protección y quien tiene la sesión ya podría cerrarla con logout.
 */
@Controller('auth/sessions')
export class SessionsController {
  constructor(
    private readonly sessionsService: SessionsService,
    private readonly auditService: AuditService,
  ) {}

  @Get()
  async list(@CurrentUser() user: AuthenticatedUser): Promise<SessionDto[]> {
    const sessions = await this.sessionsService.listActive(user.id);
    return sessions.map((s) => ({
      id: s.id,
      deviceName: s.device_name,
      createdAt: s.created_at,
      lastUsedAt: s.last_used_at,
      expiresAt: s.expires_at,
      current: s.id === user.sessionId,
    }));
  }

  /** Cierra una sesión de la cuenta. Con el id de la actual equivale a logout. */
  @HttpCode(HttpStatus.NO_CONTENT)
  @Delete(':id')
  async revoke(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
    @Param('id', new ParseUUIDPipe()) id: string,
  ): Promise<void> {
    const count = await this.sessionsService.revoke(
      id,
      'revoked_by_user',
      user.id,
    );
    // Mismo 404 si no existe, ya estaba cerrada o es de otra cuenta
    if (count === 0) {
      throw new NotFoundException('Sesión no encontrada.');
    }
    await this.auditService.record({
      userId: user.id,
      sessionId: user.sessionId,
      event: AuditEvent.AuthSessionRevoke,
      outcome: 'success',
      metadata: { current: id === user.sessionId },
      client,
    });
  }

  /** Cierra todas las sesiones excepto la actual. */
  @HttpCode(HttpStatus.OK)
  @Post('revoke-others')
  async revokeOthers(
    @CurrentUser() user: AuthenticatedUser,
    @ClientInfo() client: ClientInfoData,
  ): Promise<RevokedSessionsDto> {
    const revoked = await this.sessionsService.revokeOthers(
      user.id,
      user.sessionId,
      'revoked_by_user',
    );
    await this.auditService.record({
      userId: user.id,
      sessionId: user.sessionId,
      event: AuditEvent.AuthSessionsRevokeOthers,
      outcome: 'success',
      metadata: { revoked },
      client,
    });
    return { revoked };
  }
}
