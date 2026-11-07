import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
} from '@nestjs/common';
import {
  ClientInfo,
  type ClientInfoData,
  CurrentUser,
} from '../../../common/decorators';
import type { AuthenticatedUser } from '../../auth/strategies';
import {
  PushVaultChangesDto,
  RotateVaultKeyDto,
  VaultKeyRotatedDto,
  SyncQueryDto,
  VaultPushResponseDto,
  VaultSyncResponseDto,
} from '../dto';
import { VaultService } from '../services/vault.service';

@Controller('vault')
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  /** Cambios posteriores a la revisión `since` (o la bóveda completa). */
  @Get('sync')
  getChanges(
    @CurrentUser('id') userId: string,
    @Query() query: SyncQueryDto,
  ): Promise<VaultSyncResponseDto> {
    return this.vaultService.getChanges(userId, query.since ?? 0);
  }

  /** Cambia la clave de la bóveda (todos los elementos recifrados). */
  @HttpCode(HttpStatus.OK)
  @Post('rotate-key')
  rotateKey(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: RotateVaultKeyDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<VaultKeyRotatedDto> {
    return this.vaultService.rotateKey(
      { userId: user.id, sessionId: user.sessionId, client },
      dto,
    );
  }

  /** Aplica un lote de cambios de forma atómica (todo o nada). */
  @HttpCode(HttpStatus.OK)
  @Post('sync')
  pushChanges(
    @CurrentUser() user: AuthenticatedUser,
    @Body() dto: PushVaultChangesDto,
    @ClientInfo() client: ClientInfoData,
  ): Promise<VaultPushResponseDto> {
    return this.vaultService.pushChanges(user.id, user.sessionId, dto, client);
  }
}
